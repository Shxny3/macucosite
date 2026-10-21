"""Macuco v9.8 multi-account relay (single-process deployment).

Run only behind HTTPS/WSS when public. Auth grants use an owner-issued invite.
The relay never executes commands: GUI events are verified again by the owner app.
"""
from __future__ import annotations
import asyncio
import hashlib
import hmac
import html
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
from urllib.parse import urlparse

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, PlainTextResponse
from servidor import password_hash, dbconnect, default_data_dir, STYLE, session_for, SESS_AGE


def sha(v): return hashlib.sha256(v.encode()).hexdigest()
def safe(v):return html.escape(str(v), quote=True)

def setup_db(data_dir):
    """Prepare persistent accounts without changing credentials of existing users.

    The historical server creates admin/admin1 when the config is missing.
    A public installation must never create that insecure default account.
    """
    data_dir=Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    config=data_dir/'server_config.json'
    dbfile=data_dir/'macuco_accounts.db'
    # If a config survived but the database disappeared, refuse to silently
    # create fresh accounts. This usually means the volume is wrong/missing.
    if config.exists() and not dbfile.exists():
        raise RuntimeError('O arquivo de configuracao existe, mas macuco_accounts.db sumiu. Verifique o volume /data e restaure o backup antes de iniciar.')
    if dbfile.exists() and dbfile.stat().st_size == 0:
        raise RuntimeError('Banco macuco_accounts.db vazio. Nao vou substituir as contas existentes.')
    if dbfile.exists():
        snapshot_db(dbfile, data_dir)
    if not config.exists():
        config.write_text(json.dumps({'host_token':secrets.token_urlsafe(48),'secure_cookies':True},indent=2), encoding='utf-8')
        try:os.chmod(config,0o600)
        except OSError:pass
    with dbconnect(dbfile) as con:
        con.executescript('''
        CREATE TABLE IF NOT EXISTS users(
          username TEXT PRIMARY KEY, salt BLOB NOT NULL, passhash BLOB NOT NULL, must_change INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(
          token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, csrf TEXT NOT NULL, expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS devices(
          id TEXT PRIMARY KEY, owner TEXT NOT NULL, label TEXT NOT NULL,
          token_hash TEXT NOT NULL UNIQUE, created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS grants(
          owner TEXT NOT NULL, viewer TEXT NOT NULL, created INTEGER NOT NULL,
          PRIMARY KEY(owner,viewer));
        CREATE TABLE IF NOT EXISTS invites(
          code_hash TEXT PRIMARY KEY, owner TEXT NOT NULL, expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS pka_slots(
          device_id TEXT NOT NULL, slot INTEGER NOT NULL CHECK(slot BETWEEN 0 AND 9),
          name TEXT NOT NULL, updated INTEGER NOT NULL,
          PRIMARY KEY(device_id,slot));
        ''')
        # Migra o banco antigo sem apagar credenciais ou dispositivos.
        cols={row[1] for row in con.execute('PRAGMA table_info(devices)')}
        if 'client_key' not in cols:
            con.execute('ALTER TABLE devices ADD COLUMN client_key TEXT')
        if 'vm_slot' not in cols:
            con.execute('ALTER TABLE devices ADD COLUMN vm_slot INTEGER')
        con.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_owner_client ON devices(owner,client_key) WHERE client_key IS NOT NULL')
        con.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_owner_vm ON devices(owner,vm_slot) WHERE vm_slot IS NOT NULL')
        result=con.execute('PRAGMA quick_check').fetchone()[0]
        if result!='ok':raise RuntimeError('Banco de contas falhou na verificacao SQLite: '+str(result)[:80])
    return data_dir


def snapshot_db(dbfile,data_dir):
    """Keep a SQLite-consistent daily snapshot on the same mounted volume."""
    from datetime import datetime, timezone
    import sqlite3
    stamp=datetime.now(timezone.utc).strftime('%Y-%m-%d')
    backups=data_dir/'backups'
    backups.mkdir(exist_ok=True)
    target=backups/('macuco_accounts_'+stamp+'.db')
    if target.exists():return
    temp=backups/('macuco_accounts_'+stamp+'.db.partial')
    try:
        with sqlite3.connect(dbfile) as origin, sqlite3.connect(temp) as copy:
            origin.backup(copy)
        os.replace(temp,target)
        try:os.chmod(target,0o600)
        except OSError:pass
        existing=sorted(backups.glob('macuco_accounts_????-??-??.db'))
        for old in existing[:-7]:old.unlink()
    finally:
        if temp.exists():temp.unlink()

class Device:
    def __init__(self, id, owner, label):
        self.id=id;self.owner=owner;self.label=label
        self.agent=None;self.viewer=None;self.viewer_task=None
        self.latest=[];self.allowed=False;self.lease=None
        self.queue=None
        self.lock=asyncio.Lock()
    async def send_host(self,obj):
        if self.agent:
            try:await self.agent.send_json(obj)
            except Exception:pass
    async def queue_message(self,obj):
        if not self.queue:return
        if self.queue.full():
            try:self.queue.get_nowait()
            except asyncio.QueueEmpty:pass
        try:self.queue.put_nowait(obj)
        except asyncio.QueueFull:pass
    async def revoke(self,why='Proprietario assumiu o controle'):
        self.allowed=False;self.lease=None
        viewer=self.viewer
        self.viewer=None
        if viewer:
            try:await viewer.send_json({'type':'revoked','reason':why})
            except Exception:pass
            try:await viewer.close(code=4403,reason='Controle revogado')
            except Exception:pass


def create_app(data_dir:Path):
    data_dir=setup_db(data_dir)
    db=data_dir/'macuco_accounts.db'
    cfg=json.loads((data_dir/'server_config.json').read_text(encoding='utf-8'))
    app=FastAPI(docs_url=None,redoc_url=None,openapi_url=None)
    devices={}
    attempts={}
    app.state.devices=devices
    secure_cookie=bool(cfg.get('secure_cookies',False) or os.getenv('MACUCO_PUBLIC_DEPLOY')=='1')

    def login_guard(ip):
        now=time.monotonic();hist=[t for t in attempts.get(ip,[]) if now-t<300]
        attempts[ip]=hist
        return len(hist)<12
    def failure(ip):attempts.setdefault(ip,[]).append(time.monotonic())
    def current(req):
        with dbconnect(db) as con:return session_for(con,req.cookies.get('macuco_sid'))
    def make_session(con,username):
        sid=secrets.token_urlsafe(36)
        con.execute('INSERT INTO sessions VALUES(?,?,?,?)',(sha(sid),username,secrets.token_urlsafe(32),int(time.time())+SESS_AGE))
        return sid
    def with_cookie(response,req,sid):
        response.set_cookie('macuco_sid',sid,httponly=True,samesite='strict',secure=secure_cookie or req.url.scheme=='https',max_age=SESS_AGE,path='/')
        return response
    def page(title,body):
        return HTMLResponse(f'<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{safe(title)}</title>{STYLE}</head><body>{body}</body></html>',headers={'Cache-Control':'no-store','Content-Security-Policy':"default-src 'self'; connect-src 'self' ws: wss:; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",'X-Content-Type-Options':'nosniff'})
    def auth_body(message=''):
        return f'''<div class="center"><section class="box"><h2>MACUCO • Contas online</h2><p class="muted">Entre na sua conta ou faça o cadastro.</p><p class="error">{safe(message)}</p><form method="post" action="/login"><label>Usuário<input name="username" required maxlength="50" autocomplete="username"></label><label>Senha<input name="password" type="password" required autocomplete="current-password"></label><button>Entrar</button></form><hr><h3>Criar conta</h3><form method="post" action="/register"><label>Novo usuário<input name="username" minlength="3" maxlength="50" pattern="[A-Za-z0-9_]+" required></label><label>Senha (12+ caracteres)<input name="password" type="password" minlength="12" required></label><button class="secondary">Registrar</button></form></section></div>'''
    def require(req):
        s=current(req)
        if not s or s['must_change']:return None
        return s
    def csrf(s,form):return hmac.compare_digest(s['csrf'],str(form.get('csrf',''))) if s else False
    def device_rows(username):
        with dbconnect(db) as con:
            return con.execute('''SELECT id,owner,label,vm_slot FROM devices
                WHERE owner=? OR owner IN(SELECT owner FROM grants WHERE viewer=?)
                ORDER BY owner,label''',(username,username)).fetchall()
    def dashboard_body(s,notice=''):
        username=s['username'];token=s['csrf']
        rows=device_rows(username)
        with dbconnect(db) as con:
            saved=con.execute('SELECT device_id,slot,name FROM pka_slots WHERE device_id IN (SELECT id FROM devices WHERE owner=? OR owner IN(SELECT owner FROM grants WHERE viewer=?)) ORDER BY slot',(username,username)).fetchall()
        pka_by_device={}
        for entry in saved:pka_by_device.setdefault(entry['device_id'],[]).append(entry)
        cards=''.join(f'''<article class="card"><strong>{safe(r['label'])}</strong><p class="muted">Dono: {safe(r['owner'])}</p><p><strong>{'ONLINE / LIBERADO' if devices.get(r['id']) and devices[r['id']].agent and devices[r['id']].allowed else ('ONLINE / BLOQUEADO' if devices.get(r['id']) and devices[r['id']].agent else 'OFFLINE')}</strong></p><a href="/control/{safe(r['id'])}">Controlar esta VM</a><p class="muted">Contas PKA salvas: {len(pka_by_device.get(r['id'],[]))}/10</p><div class="muted" style="font-size:12px">{safe(' · '.join(f"{int(item['slot'])+1}: {item['name']}" for item in pka_by_device.get(r['id'],[])))}</div></article>''' for r in rows) or '<p class="muted">Nenhum Macuco vinculado. Gere um token para o seu aplicativo, ou aceite um convite.</p>'
        own=[r for r in rows if r['owner']==username]
        revoke=''.join(f'''<form method="post" action="/devices/delete"><input type="hidden" name="csrf" value="{safe(token)}"><input type="hidden" name="device" value="{safe(r['id'])}"><button class="secondary">Desvincular {safe(r['label'])}</button></form>''' for r in own)
        pka_forms=''.join(f"""<form method="post" action="/pka/slot" style="padding:12px 0;border-bottom:1px solid #34475c"><input type="hidden" name="csrf" value="{safe(token)}"><input type="hidden" name="device" value="{safe(r['id'])}"><strong>{safe(r['label'])}</strong><label>Conta PKA (1 a 10)<input type="number" name="slot" min="1" max="10" required value="1"></label><label>Nome de exibição (vazio remove)<input name="name" maxlength="64" placeholder="Nome da conta"></label><button class="secondary">Salvar nome</button></form>""" for r in own)
        with dbconnect(db) as con:grants=con.execute('SELECT viewer FROM grants WHERE owner=?',(username,)).fetchall()
        permissions=''.join(f'''<form method="post" action="/grants/revoke"><input type="hidden" name="csrf" value="{safe(token)}"><input type="hidden" name="viewer" value="{safe(row['viewer'])}"><button class="secondary">Revogar acesso de {safe(row['viewer'])}</button></form>''' for row in grants)
        return f'''<header><strong>MACUCO • Conta: {safe(username)}</strong><form method="post" action="/logout"><input type="hidden" name="csrf" value="{safe(token)}"><button class="secondary">Sair</button></form></header>
<main><p class="muted">{safe(notice)}</p><h2>Minhas VMs e acessos autorizados</h2><p class="muted">Abra o Macuco v9.9.13 em cada VM e use Vincular / Abrir Macuco desta VM. Todos entram com seu usuario, mas cada instalacao tem identidade propria. Atualize a pagina para consultar o status.</p><section class="grid">{cards}</section><hr><h3>Gerenciar VMs</h3><p class="muted">Nao e necessario gerar tokens manualmente: cada VM autentica pelo aplicativo e cria sua vinculacao. Para reconectar uma VM antiga, use a mesma instalacao; remova o vinculo somente se precisar substituir a VM definitivamente.</p>{revoke}
<hr><h3>Convidar amigo</h3><p class="muted">Gere um código de convite com validade de 15 minutos. O amigo usa sua própria conta, nunca sua senha.</p><form method="post" action="/invites/new"><input type="hidden" name="csrf" value="{safe(token)}"><button>Gerar convite</button></form><h3>Usar convite recebido</h3><form method="post" action="/invites/redeem"><input type="hidden" name="csrf" value="{safe(token)}"><label>Código de convite<input name="code" required autocomplete="off"></label><button>Autorizar meu acesso</button></form>{permissions}<hr><h3>Contas PKA cadastradas (nomes)</h3><p class="muted">Guarde o nome de exibição de cada uma das 10 posições de um Macuco Pai. Isso não armazena senha do PKA nem substitui a vinculação no aplicativo local.</p>{pka_forms}</main>'''

    @app.get('/health')
    async def health():
        try:
            with dbconnect(db) as con:con.execute('SELECT 1').fetchone()
        except Exception:
            return JSONResponse({'ok':False,'service':'macuco-render-10vm','storage':'unavailable'},503)
        return {'ok':True,'service':'macuco-render-10vm','storage':'persistent-configured'}

    @app.get('/')
    async def root(req:Request):return RedirectResponse('/dashboard' if require(req) else '/login',303)
    @app.get('/login')
    async def login_get(req:Request):return RedirectResponse('/dashboard',303) if require(req) else page('Login',auth_body())
    @app.post('/register')
    async def register(req:Request):
        ip=req.client.host if req.client else '?'
        if not login_guard(ip):return page('Cadastro',auth_body('Aguarde 5 minutos.'))
        form=await req.form();username=str(form.get('username','')).strip();password=str(form.get('password',''))
        if not (3<=len(username)<=50 and all(c.isascii() and (c.isalnum() or c=='_') for c in username) and 12<=len(password)<=256):return page('Cadastro',auth_body('Usuário inválido ou senha muito curta.'))
        with dbconnect(db) as con:
            if con.execute('SELECT 1 FROM users WHERE username=?',(username,)).fetchone():
                failure(ip);return page('Cadastro',auth_body('Usuário indisponível.'))
            salt=os.urandom(16)
            con.execute('INSERT INTO users VALUES(?,?,?,0)',(username,salt,password_hash(password,salt)))
            sid=make_session(con,username)
        return with_cookie(RedirectResponse('/dashboard',303),req,sid)
    @app.post('/login')
    async def login_post(req:Request):
        ip=req.client.host if req.client else '?'
        if not login_guard(ip):return page('Login',auth_body('Aguarde 5 minutos.'))
        form=await req.form();username=str(form.get('username',''))[:50];password=str(form.get('password',''))
        with dbconnect(db) as con:
            u=con.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
            if not u or not hmac.compare_digest(password_hash(password,u['salt']),u['passhash']):
                failure(ip);return page('Login',auth_body('Usuário ou senha incorretos.'))
            sid=make_session(con,username)
            must=bool(u['must_change'])
        attempts.pop(ip,None)
        return with_cookie(RedirectResponse('/change-password' if must else '/dashboard',303),req,sid)
    @app.post('/api/login')
    async def app_login(req:Request):
        ip=req.client.host if req.client else '?'
        if not login_guard(ip):return JSONResponse({'error':'Muitas tentativas'},429)
        try:data=await req.json()
        except (ValueError,TypeError):return JSONResponse({'error':'JSON invalido'},400)
        username=str(data.get('username',''))[:50];password=str(data.get('password',''))
        with dbconnect(db) as con:
            u=con.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
            if not u or not hmac.compare_digest(password_hash(password,u['salt']),u['passhash']):
                failure(ip);return JSONResponse({'error':'Credenciais invalidas'},401)
            if u['must_change']:return JSONResponse({'error':'Troque a senha inicial no site antes.'},403)
            sid=make_session(con,username)
        attempts.pop(ip,None)
        return with_cookie(JSONResponse({'ok':True,'sid':sid}),req,sid)
    # Login/cadastro nativos do Macuco (sem abrir navegador).
    @app.post('/api/register')
    async def api_register(req:Request):
        ip=req.client.host if req.client else '?'
        if not login_guard(ip):return JSONResponse({'error':'Muitas tentativas. Tente novamente em alguns minutos.'},429)
        try:data=await req.json()
        except (ValueError,TypeError):return JSONResponse({'error':'JSON invalido'},400)
        if not isinstance(data,dict):return JSONResponse({'error':'JSON invalido'},400)
        username=str(data.get('username','')).strip();password=str(data.get('password',''))
        if not (3<=len(username)<=50 and all(c.isascii() and (c.isalnum() or c=='_') for c in username)
                and 12<=len(password)<=256):
            return JSONResponse({'error':'Usuario (3-50 letras, numeros ou _) e senha (12+ caracteres) obrigatorios.'},400)
        with dbconnect(db) as con:
            if con.execute('SELECT 1 FROM users WHERE username=?',(username,)).fetchone():
                return JSONResponse({'error':'Esse usuario ja existe.'},409)
            salt=os.urandom(16)
            con.execute('INSERT INTO users VALUES(?,?,?,0)',(username,salt,password_hash(password,salt)))
            sid=make_session(con,username)
        return with_cookie(JSONResponse({'ok':True,'sid':sid,'username':username}),req,sid)

    @app.post('/api/devices/bootstrap')
    async def api_bootstrap(req:Request):
        """Register/reconnect ONE VM for an authenticated account (max 10).

        A stable random installation key isolates different Windows VMs. A slot
        cannot silently switch to a different VM. Reconnect rotates its bearer
        token only while the previous device is offline.
        """
        s=require(req)
        if not s:return JSONResponse({'error':'Entre na sua conta antes de vincular uma VM.'},401)
        try: data=await req.json()
        except (TypeError,ValueError):data={}
        if not isinstance(data,dict):data={}
        owner=s['username']
        vm_slot=data.get('vm_slot')
        client_key=data.get('client_id')
        if type(vm_slot) is not int or not 1<=vm_slot<=10:
            return JSONResponse({'error':'Escolha VM 1 a 10.'},400)
        if not isinstance(client_key,str) or len(client_key)!=32 or any(c not in '0123456789abcdef' for c in client_key):
            return JSONResponse({'error':'Identificador da instalacao invalido.'},400)
        label=f'VM {vm_slot:02d}'
        secret=secrets.token_urlsafe(48)
        with dbconnect(db) as con:
            con.execute('BEGIN IMMEDIATE')
            row=con.execute('SELECT id,vm_slot FROM devices WHERE owner=? AND client_key=?',(owner,client_key)).fetchone()
            occupied=con.execute('SELECT id,client_key FROM devices WHERE owner=? AND vm_slot=?',(owner,vm_slot)).fetchone()
            if row and row['vm_slot'] != vm_slot:
                return JSONResponse({'error':f'Este computador ja foi registrado como VM {row["vm_slot"]}. Selecione esse numero.'},409)
            if occupied and (not row or occupied['id']!=row['id']):
                return JSONResponse({'error':f'VM {vm_slot} ja pertence a outra instalacao. Use outra posicao ou desvincule a anterior no site.'},409)
            if row:
                device_id=row['id']
                live=devices.get(device_id)
                if live and live.agent:
                    return JSONResponse({'error':'Esta VM ja esta conectada. Feche a instancia anterior antes de reconectar.'},409)
                con.execute('UPDATE devices SET token_hash=?,label=? WHERE id=?',(sha(secret),label,device_id))
            else:
                count=con.execute('SELECT COUNT(*) FROM devices WHERE owner=? AND vm_slot IS NOT NULL',(owner,)).fetchone()[0]
                if count>=10:return JSONResponse({'error':'Limite de 10 VMs por conta atingido.'},409)
                device_id=secrets.token_urlsafe(12)
                con.execute('INSERT INTO devices(id,owner,label,token_hash,created,client_key,vm_slot) VALUES(?,?,?,?,?,?,?)',
                    (device_id,owner,label,sha(secret),int(time.time()),client_key,vm_slot))
        return JSONResponse({'ok':True,'id':device_id,'token':secret,'vm_slot':vm_slot,'label':label})

    @app.post('/api/logout')
    async def api_logout(req:Request):
        s=current(req)
        if s:
            with dbconnect(db) as con:con.execute('DELETE FROM sessions WHERE token_hash=?',(s['token_hash'],))
        response=JSONResponse({'ok':True});response.delete_cookie('macuco_sid');return response

    @app.get('/change-password')
    async def change_get(req:Request):
        s=current(req)
        if not s:return RedirectResponse('/login',303)
        return page('Trocar senha',f'''<div class="center"><form class="box" method="post" action="/change-password"><h2>Troque a senha inicial</h2><input type="hidden" name="csrf" value="{safe(s['csrf'])}"><label>Senha atual<input type="password" name="old" required></label><label>Nova senha (12+ caracteres)<input type="password" name="new" minlength="12" required></label><button>Trocar senha</button></form></div>''')
    @app.post('/change-password')
    async def change_post(req:Request):
        s=current(req)
        if not s:return RedirectResponse('/login',303)
        form=await req.form()
        if not csrf(s,form):return PlainTextResponse('CSRF invalido',403)
        old=str(form.get('old',''));new=str(form.get('new',''))
        with dbconnect(db) as con:
            u=con.execute('SELECT * FROM users WHERE username=?',(s['username'],)).fetchone()
            if not hmac.compare_digest(password_hash(old,u['salt']),u['passhash']) or len(new)<12 or new==old or new=='admin1':return PlainTextResponse('Senha inválida; volte e tente outra.',400)
            salt=os.urandom(16)
            con.execute('UPDATE users SET salt=?,passhash=?,must_change=0 WHERE username=?',(salt,password_hash(new,salt),s['username']))
            con.execute('DELETE FROM sessions WHERE username=? AND token_hash!=?',(s['username'],s['token_hash']))
        return RedirectResponse('/dashboard',303)
    @app.post('/logout')
    async def logout(req:Request):
        s=current(req)
        if s:
            f=await req.form()
            if not csrf(s,f):return PlainTextResponse('CSRF invalido',403)
            with dbconnect(db) as con:con.execute('DELETE FROM sessions WHERE token_hash=?',(s['token_hash'],))
        r=RedirectResponse('/login',303);r.delete_cookie('macuco_sid');return r
    @app.get('/dashboard')
    async def dashboard(req:Request):
        s=require(req)
        if not s:return RedirectResponse('/change-password' if current(req) else '/login',303)
        return page('Macuco Central',dashboard_body(s))
    @app.post('/devices/new')
    async def new_device(req:Request):
        s=require(req)
        if not s:return RedirectResponse('/login',303)
        form=await req.form()
        if not csrf(s,form):return PlainTextResponse('CSRF invalido',403)
        label=str(form.get('label','')).strip()[:64]
        if not label:return PlainTextResponse('Nome invalido',400)
        secret=secrets.token_urlsafe(48);device_id=secrets.token_urlsafe(12)
        with dbconnect(db) as con:con.execute('INSERT INTO devices VALUES(?,?,?,?,?)',(device_id,s['username'],label,sha(secret),int(time.time())))
        return page('Token criado',f'''<main><h2>Token do Macuco Pai: {safe(label)}</h2><p>Copie agora; o servidor não guarda este valor em texto.</p><pre style="white-space:pre-wrap;overflow-wrap:anywhere">{safe(secret)}</pre><p><a href="/dashboard">Voltar</a></p></main>''')
    @app.post('/devices/delete')
    async def delete_device(req:Request):
        s=require(req)
        if not s:return RedirectResponse('/login',303)
        form=await req.form()
        if not csrf(s,form):return PlainTextResponse('CSRF invalido',403)
        device_id=str(form.get('device',''))
        with dbconnect(db) as con:
            con.execute('DELETE FROM pka_slots WHERE device_id=? AND device_id IN (SELECT id FROM devices WHERE owner=?)',(device_id,s['username']))
            con.execute('DELETE FROM devices WHERE id=? AND owner=?',(device_id,s['username']))
        dev=devices.get(device_id)
        if dev:
            await dev.revoke('Dispositivo desvinculado')
            await dev.send_host({'type':'disconnect','reason':'Dispositivo removido'})
        return RedirectResponse('/dashboard',303)
    @app.post('/invites/new')
    async def invite(req:Request):
        s=require(req)
        if not s:return RedirectResponse('/login',303)
        form=await req.form()
        if not csrf(s,form):return PlainTextResponse('CSRF invalido',403)
        code=secrets.token_urlsafe(24)
        with dbconnect(db) as con:con.execute('INSERT INTO invites VALUES(?,?,?)',(sha(code),s['username'],int(time.time())+900))
        return page('Convite criado',f'''<main><h2>Convite para acessar seus Macucos</h2><p>Validade: 15 minutos, uso único. Envie somente a alguém de confiança.</p><pre>{safe(code)}</pre><p><a href="/dashboard">Voltar</a></p></main>''')
    @app.post('/invites/redeem')
    async def redeem(req:Request):
        s=require(req)
        if not s:return RedirectResponse('/login',303)
        form=await req.form()
        if not csrf(s,form):return PlainTextResponse('CSRF invalido',403)
        code=str(form.get('code',''))[:200]
        with dbconnect(db) as con:
            row=con.execute('SELECT owner FROM invites WHERE code_hash=? AND expires>?',(sha(code),int(time.time()))).fetchone()
            if not row:return PlainTextResponse('Convite inválido ou expirado',400)
            con.execute('DELETE FROM invites WHERE code_hash=?',(sha(code),))
            if row['owner']!=s['username']:con.execute('INSERT OR IGNORE INTO grants VALUES(?,?,?)',(row['owner'],s['username'],int(time.time())))
        return RedirectResponse('/dashboard',303)
    @app.post('/grants/revoke')
    async def revoke_grant(req:Request):
        s=require(req)
        if not s:return RedirectResponse('/login',303)
        form=await req.form()
        if not csrf(s,form):return PlainTextResponse('CSRF invalido',403)
        viewer=str(form.get('viewer',''))[:50]
        with dbconnect(db) as con:con.execute('DELETE FROM grants WHERE owner=? AND viewer=?',(s['username'],viewer))
        for device in list(devices.values()):
            if device.owner==s['username'] and device.viewer is not None:
                await device.revoke('Proprietario revogou acesso')
                await device.send_host({'type':'control_end'})
        return RedirectResponse('/dashboard',303)
    @app.post('/pka/slot')
    async def save_pka_slot(req:Request):
        s=require(req)
        if not s:return RedirectResponse('/login',303)
        form=await req.form()
        if not csrf(s,form):return PlainTextResponse('CSRF invalido',403)
        device=str(form.get('device',''))
        name=str(form.get('name','')).strip()
        try:slot=int(str(form.get('slot','0')))-1
        except ValueError:return PlainTextResponse('Posicao invalida',400)
        if not (0<=slot<10 and len(name)<=64):return PlainTextResponse('Conta PKA invalida',400)
        with dbconnect(db) as con:
            if not con.execute('SELECT 1 FROM devices WHERE id=? AND owner=?',(device,s['username'])).fetchone():
                return PlainTextResponse('Sem permissao',403)
            if name:
                con.execute('INSERT INTO pka_slots(device_id,slot,name,updated) VALUES(?,?,?,?) ON CONFLICT(device_id,slot) DO UPDATE SET name=excluded.name,updated=excluded.updated',(device,slot,name,int(time.time())))
            else:
                con.execute('DELETE FROM pka_slots WHERE device_id=? AND slot=?',(device,slot))
        return RedirectResponse('/dashboard',303)

    @app.get('/api/pka-accounts')
    async def get_pka_accounts(req:Request):
        s=require(req)
        if not s:return JSONResponse({'error':'Nao autorizado'},401)
        with dbconnect(db) as con:
            rows=con.execute("SELECT p.device_id,p.slot,p.name,d.owner FROM pka_slots p JOIN devices d ON d.id=p.device_id WHERE d.owner=? OR d.owner IN(SELECT owner FROM grants WHERE viewer=?) ORDER BY d.owner,p.device_id,p.slot",(s['username'],s['username'])).fetchall()
        return {'accounts':[{'device_id':r['device_id'],'slot':r['slot'],'name':r['name'],'owner':r['owner']} for r in rows]}

    @app.get('/api/account')
    async def api_account(req:Request):
        s=require(req)
        if not s:return JSONResponse({'error':'Nao autorizado'},401)
        with dbconnect(db) as con:
            linked=con.execute('SELECT COUNT(*) FROM devices WHERE owner=?',(s['username'],)).fetchone()[0]
        return {'ok':True,'username':s['username'],'registered':True,'devices':linked}

    @app.get('/api/devices')
    async def api_devices(req:Request):
        s=require(req)
        if not s:return JSONResponse({'error':'Nao autorizado'},401)
        return {'devices':[{'id':r['id'],'label':r['label'],'owner':r['owner'],'online':bool(devices.get(r['id']) and devices[r['id']].agent),'available':bool(devices.get(r['id']) and devices[r['id']].allowed),'vm_slot':r['vm_slot']} for r in device_rows(s['username'])]}
    def can_view(username,owner):
        if username==owner:return True
        with dbconnect(db) as con:return bool(con.execute('SELECT 1 FROM grants WHERE owner=? AND viewer=?',(owner,username)).fetchone())
    def lookup_device(device_id):
        with dbconnect(db) as con:return con.execute('SELECT id,owner,label FROM devices WHERE id=?',(device_id,)).fetchone()

    async def ws_origin_ok(ws):
        origin=ws.headers.get('origin','')
        return origin and urlparse(origin).netloc.lower()==ws.headers.get('host','').lower() and urlparse(origin).scheme in ('http','https')
    @app.websocket('/ws/agent_v98')
    async def agent(ws:WebSocket):
        header=ws.headers.get('authorization','')
        if not header.startswith('Bearer '):await ws.close(code=1008);return
        secret=header[7:]
        with dbconnect(db) as con:r=con.execute('SELECT id,owner,label FROM devices WHERE token_hash=?',(sha(secret),)).fetchone()
        if not r:await ws.close(code=1008);return
        dev=devices.setdefault(r['id'],Device(r['id'],r['owner'],r['label']))
        async with dev.lock:
            if dev.agent:await ws.close(code=1008);return
            await ws.accept()
            dev.agent=ws;dev.allowed=False;dev.lease=None
        try:
            while True:
                raw=await ws.receive_text()
                if len(raw)>3_000_000:continue
                try:m=json.loads(raw)
                except (ValueError,TypeError):continue
                if not isinstance(m,dict):continue
                kind=m.get('type')
                if kind=='state':
                    dev.allowed=bool(m.get('armed'))
                    if not dev.allowed and dev.viewer:await dev.revoke('Controle revogado pelo dono')
                elif kind=='ui_frame':
                    if dev.viewer and dev.lease and type(m.get('w')) is int and type(m.get('h')) is int and 1<=m['w']<=6000 and 1<=m['h']<=6000 and isinstance(m.get('jpg'),str) and len(m['jpg'])<=2_800_000:
                        await dev.queue_message({'type':'ui_frame','w':m['w'],'h':m['h'],'jpg':m['jpg']})
                elif kind=='owner_input':
                    await dev.revoke('O proprietário começou a usar o Macuco')
                    await dev.send_host({'type':'control_end'})
                elif kind=='frame':
                    # Optional 10 independent VM preview frames, if the viewer chooses slots.
                    if dev.viewer and isinstance(m.get('jpg'),str) and len(m['jpg'])<2_800_000 and type(m.get('slot')) is int and 0<=m['slot']<10:
                        await dev.queue_message({'type':'frame','slot':m['slot'],'jpg':m['jpg']})
                elif kind=='accounts':
                    if isinstance(m.get('accounts'),list):
                        dev.latest=[{'slot':a.get('slot'),'name':str(a.get('name',''))[:80],'running':bool(a.get('running'))} for a in m['accounts'][:10] if isinstance(a,dict) and type(a.get('slot')) is int and 0<=a['slot']<10]
                        with dbconnect(db) as con:
                            for a in dev.latest:
                                name=a['name'].strip()[:64]
                                if name:
                                    con.execute('INSERT INTO pka_slots(device_id,slot,name,updated) VALUES(?,?,?,?) ON CONFLICT(device_id,slot) DO UPDATE SET name=excluded.name,updated=excluded.updated',(dev.id,a['slot'],name,int(time.time())))
        except (WebSocketDisconnect,RuntimeError):pass
        finally:
            if dev.agent is ws:
                dev.agent=None
                await dev.revoke('Macuco Pai desconectado')
    @app.websocket('/ws/control/{device_id}')
    async def control(ws:WebSocket,device_id:str):
        if not await ws_origin_ok(ws):await ws.close(code=1008);return
        with dbconnect(db) as con:s=session_for(con,ws.cookies.get('macuco_sid'))
        r=lookup_device(device_id)
        if not s or s['must_change'] or not r or not can_view(s['username'],r['owner']):await ws.close(code=1008);return
        dev=devices.get(device_id)
        # An authenticated viewer gets a useful error instead of an opaque
        # WebSocket handshake failure. Never disclose device state to people
        # who did not pass the auth/grant checks above.
        if not dev or not dev.agent:
            await ws.accept()
            await ws.send_json({'type':'unavailable','reason':'Macuco Pai offline: o aplicativo principal nao esta conectado ao servidor.'})
            await ws.close(code=4409,reason='Macuco Pai offline')
            return
        async with dev.lock:
            if not dev.agent:
                why='Macuco Pai offline: a conexao do aplicativo caiu.'
            elif not dev.allowed:
                why='Controle remoto indisponivel: o Macuco Pai nao liberou acesso ou o dono retomou o controle.'
            elif dev.viewer:
                why='Macuco ja esta sendo controlado por outra sessao. Feche outros Macucos Filhos ou abas de controle e tente novamente.'
            else:
                why=None
            if why:
                await ws.accept()
                await ws.send_json({'type':'unavailable','reason':why})
                await ws.close(code=4409,reason='Controle indisponivel')
                return
            await ws.accept()
            dev.viewer=ws;dev.queue=asyncio.Queue(maxsize=3)
            lease=secrets.token_urlsafe(22);dev.lease=lease
        await dev.send_host({'type':'control_begin','lease':lease})
        await dev.queue_message({'type':'connected','name':dev.label,'owner':dev.owner})
        async def sender():
            while True:await ws.send_json(await dev.queue.get())
        task=asyncio.create_task(sender())
        rate=[]
        try:
            while dev.viewer is ws and dev.lease==lease:
                raw=await ws.receive_text()
                if len(raw)>2000:continue
                try:m=json.loads(raw)
                except (TypeError,ValueError):continue
                if not isinstance(m,dict) or m.get('type')!='ui_action':continue
                now=time.monotonic();rate=[t for t in rate if now-t<1]
                if len(rate)>=80:continue
                rate.append(now)
                act=m.get('action');obj={'type':'ui_action','lease':lease,'action':act}
                if act in ('click','move','press','release'):
                    x,y=m.get('x'),m.get('y')
                    if type(x) not in (int,float) or type(y) not in (int,float) or not (0<=x<=1 and 0<=y<=1):continue
                    obj.update(x=x,y=y)
                    if act in ('click','press','release'):
                        if m.get('button','left') not in ('left','right'):continue
                        obj['button']=m.get('button','left')
                elif act=='key':
                    key=m.get('key')
                    if type(key) is not int or not 0<=key<=0x10ffff:continue
                    obj['key']=key
                    obj['text']=str(m.get('text',''))[:8]
                elif act=='scroll':
                    delta=m.get('delta')
                    if type(delta) is not int or not -1200<=delta<=1200:continue
                    obj['delta']=delta
                else:continue
                if dev.viewer is ws and dev.lease==lease and dev.allowed:
                    await dev.send_host(obj)
        except (WebSocketDisconnect,RuntimeError):pass
        finally:
            task.cancel()
            if dev.viewer is ws:
                dev.viewer=None;dev.lease=None;dev.queue=None
                await dev.send_host({'type':'control_end'})

    CONTROL_HTML='''<header><strong>MACUCO • Controle remoto completo</strong><a href="/dashboard">Voltar</a></header><main><p id="status" class="muted">Conectando...</p><p class="muted">Clique nos menus e botões da imagem. Teclado disponível ao focar o painel. Assim que o dono interagir localmente, sua sessão é encerrada. Os bots continuam no PC dele.</p><div id="surface" style="width:100%;max-width:1600px;aspect-ratio:16/9;background:#050c15;outline:2px solid #465b70;overflow:hidden;display:grid;place-items:center" tabindex="0"><img id="screen" style="max-width:100%;max-height:100%;object-fit:contain"></div></main>
<script>
const host=document.getElementById('surface'),img=document.getElementById('screen'),status=document.getElementById('status');let active=false,receivedFinalReason=false;
const socket=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host+'/ws/control/DEVICE_PLACEHOLDER');
function send(data){if(active&&socket.readyState===1)socket.send(JSON.stringify({...data,type:'ui_action'}))}
function pos(e){let r=img.getBoundingClientRect();return {x:(e.clientX-r.left)/r.width,y:(e.clientY-r.top)/r.height}}
let drag=null;
host.addEventListener('pointerdown',e=>{e.preventDefault();host.focus();if(!img.naturalWidth)return;let p=pos(e);if(p.x>=0&&p.x<=1&&p.y>=0&&p.y<=1){drag=e.button===2?'right':'left';host.setPointerCapture(e.pointerId);send({action:'press',...p,button:drag})}});
host.addEventListener('pointermove',e=>{if(!drag||!img.naturalWidth)return;let p=pos(e);send({action:'move',x:Math.max(0,Math.min(1,p.x)),y:Math.max(0,Math.min(1,p.y))})});
function finish(e){if(!drag)return;let p=pos(e);send({action:'release',x:Math.max(0,Math.min(1,p.x)),y:Math.max(0,Math.min(1,p.y)),button:drag});drag=null}
host.addEventListener('pointerup',finish);host.addEventListener('pointercancel',finish);
host.addEventListener('contextmenu',e=>e.preventDefault());
host.addEventListener('keydown',e=>{e.preventDefault();if(e.repeat)return;send({action:'key',key:e.keyCode,text:e.key.length===1?e.key:''})});
// Scroll is opt-in, to avoid unexpectedly scrolling the host while navigating the page.
host.addEventListener('wheel',e=>{e.preventDefault();send({action:'scroll',delta:Math.max(-1200,Math.min(1200,Math.round(-e.deltaY)))})},{passive:false});
socket.onopen=()=>status.textContent='Aguardando permissão do Macuco Pai...';
socket.onmessage=e=>{let m=JSON.parse(e.data);if(m.type==='connected'){active=true;status.textContent='Conectado: '+m.name+' • '+m.owner}else if(m.type==='ui_frame'){img.src='data:image/jpeg;base64,'+m.jpg}else if(m.type==='revoked'||m.type==='unavailable'){receivedFinalReason=true;active=false;status.textContent=m.reason||'Controle indisponível';img.removeAttribute('src')}};
socket.onclose=e=>{
  active=false;
  // Do not overwrite the actual owner-revocation or unavailability reason.
  if(receivedFinalReason)return;
  if(e.code===1008)status.textContent='Acesso negado (código 1008): confira login, convite e sessão do navegador.';
  else if(e.code===4409)status.textContent='Controle indisponível (código 4409): confira se o Pai está online, liberado e sem outro Filho conectado.';
  else status.textContent='WebSocket encerrado (código '+e.code+'). Não significa necessariamente que o dono clicou. Verifique a conexão e os logs do Railway.';
};
</script>'''
    @app.get('/control/{device_id}')
    async def page_control(req:Request,device_id:str):
        s=require(req);r=lookup_device(device_id)
        if not s:return RedirectResponse('/login',303)
        if not r or not can_view(s['username'],r['owner']):return PlainTextResponse('Sem acesso a este Macuco',403)
        return page('Controle Macuco',CONTROL_HTML.replace('DEVICE_PLACEHOLDER',safe(device_id)))
    return app

BASE=default_data_dir()
app=create_app(BASE)
