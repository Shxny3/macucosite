"""Macuco relay login server (independent of Macuco desktop app version).

Run behind a TLS reverse proxy before exposing over the internet. The server
relays ONLY account frames/status and narrowly-scoped account commands.
"""
from __future__ import annotations
import asyncio
import hashlib
import hmac
import html
from contextlib import contextmanager
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
from urllib.parse import urlparse

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse

SESS_AGE = 8 * 3600
BCRYPT_NOTE = 'Uses scrypt + per-user salt, not plaintext passwords.'
VALID_KEYS=(set(range(0x30,0x3A))|set(range(0x41,0x5B))|
            set(range(0x70,0x7C))|{0x08,0x09,0x0D,0x1B,0x20,0x25,0x26,0x27,0x28,0xBD,0xBB,0xDE})
STYLE='''<style>
:root{font-family:system-ui,Arial;background:#0e1520;color:#f2f4f9;color-scheme:dark}*{box-sizing:border-box}
body{margin:0;min-height:100vh}a{color:#9adcfb}.center{display:grid;place-items:center;min-height:100vh;padding:20px}
.box{background:#1c2939;border:1px solid #405165;border-radius:16px;padding:26px;max-width:480px;width:100%;box-shadow:0 12px 40px #0005}
input{background:#101a26;color:white;border:1px solid #526579;border-radius:8px;padding:11px;width:100%;margin:6px 0 17px}
button{cursor:pointer;background:#f27863;color:#121820;border:0;border-radius:9px;padding:10px 16px;font-weight:700}
button:disabled{opacity:.45}.secondary{background:#273b4b;color:white}.muted{color:#a9bbcd}.error{color:#ffaaa0}
header{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:16px 22px;background:#182638;flex-wrap:wrap}
main{padding:16px;max-width:1800px;margin:auto}.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(265px,1fr));gap:12px}
.card{background:#182638;border:1px solid #405165;border-radius:12px;padding:12px;min-width:0}
.preview{position:relative;aspect-ratio:16/10;background:#070b11;border:1px solid #36495b;border-radius:8px;overflow:hidden;display:flex;justify-content:center;align-items:center;cursor:crosshair;outline:none}
.preview:focus{border:2px solid #f27863}.preview img{width:100%;height:100%;object-fit:contain}.preview span{color:#647c92;position:absolute}
.cardbar{display:flex;justify-content:space-between;gap:8px;align-items:center;margin-bottom:8px}.state{font-size:12px;color:#adc2d2;white-space:nowrap}
.actions{display:flex;gap:8px;margin-top:10px}.actions button{flex:1}.hidden{display:none!important}
</style>'''

def password_hash(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode('utf-8'), salt=salt, n=2**14, r=8, p=1, dklen=32)

@contextmanager
def dbconnect(path):
    con = sqlite3.connect(path, timeout=10)
    con.row_factory=sqlite3.Row
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()

def init_server(data_dir: Path):
    data_dir.mkdir(exist_ok=True,parents=True)
    conf=data_dir/'server_config.json'
    if conf.exists():
        raise RuntimeError('Servidor ja foi configurado; nao vou substituir as credenciais.')
    token=secrets.token_urlsafe(48)
    conf.write_text(json.dumps({'host_token':token,'secure_cookies':False},indent=2),encoding='utf-8')
    try:os.chmod(conf,0o600)
    except OSError:pass
    db=data_dir/'macuco_accounts.db'
    with dbconnect(db) as con:
        con.executescript('''CREATE TABLE IF NOT EXISTS users(
            username TEXT PRIMARY KEY, salt BLOB NOT NULL, passhash BLOB NOT NULL, must_change INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS sessions(
            token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, csrf TEXT NOT NULL,expires INTEGER NOT NULL);''')
        salt=os.urandom(16)
        con.execute('INSERT OR IGNORE INTO users VALUES (?,?,?,1)',('admin',salt,password_hash('admin1',salt)))
    return token

class Relay:
    def __init__(self):
        self.agent=None
        self.agent_lock=asyncio.Lock()
        self.viewers=set()
        self.allowed_slots=set()
        self.metadata=[]
    async def send_agent(self,obj):
        async with self.agent_lock:
            if self.agent is not None:
                try: await self.agent.send_text(json.dumps(obj,separators=(',',':')))
                except Exception:pass
    async def announce(self,obj):
        payload=json.dumps(obj,separators=(',',':'),ensure_ascii=False)
        for q in list(self.viewers):
            if q.full():
                try:q.get_nowait()   # Never build an unbounded video backlog.
                except asyncio.QueueEmpty:pass
            try:q.put_nowait(payload)
            except asyncio.QueueFull:pass

def page(title,body):
    return HTMLResponse(f'<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)}</title>{STYLE}</head><body>{body}</body></html>',headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'self'; img-src 'self' data:; connect-src 'self' ws: wss:; style-src 'unsafe-inline' 'self'; script-src 'unsafe-inline' 'self'; base-uri 'none'; frame-ancestors 'none'"})

def login_page(message=''):
    error=f'<p class="error">{html.escape(message)}</p>' if message else ''
    return page('Login Macuco',f'''<div class="center"><form class="box" method="post" action="/login"><h1>MACUCO • Login</h1><p class="muted">Acesse suas contas compartilhadas.</p>{error}<label>Usuário<input name="username" autocomplete="username" required maxlength="80"></label><label>Senha<input name="password" type="password" autocomplete="current-password" required></label><button type="submit">Entrar</button></form></div>''')

def session_for(con,sid):
    if not sid:return None
    h=hashlib.sha256(sid.encode()).hexdigest()
    row=con.execute('''SELECT s.*,u.must_change FROM sessions s JOIN users u ON s.username=u.username WHERE token_hash=? AND expires>?''',(h,int(time.time()))).fetchone()
    return row

def csrf_page(csrf,message=''):
    error=f'<p class="error">{html.escape(message)}</p>' if message else ''
    return page('Alterar senha',f'''<div class="center"><form class="box" method="post" action="/change-password"><h1>Defina sua senha</h1><p class="muted">A senha inicial admin1 precisa ser substituída antes de acessar as contas.</p>{error}<input type="hidden" name="csrf" value="{html.escape(csrf)}"><label>Senha atual<input type="password" name="old" autocomplete="current-password" required></label><label>Nova senha (mínimo 12 caracteres)<input type="password" name="new" autocomplete="new-password" minlength="12" required></label><button>Salvar senha</button></form></div>''')

DASHBOARD='''<header><div><strong>MACUCO • Central Remota</strong> <span class="muted">Controle individual de até 10 contas</span></div><form method="post" action="/logout"><input type="hidden" name="csrf" value="CSRF_PLACEHOLDER"><button class="secondary">Sair</button></form></header>
<main><p id="connection" class="muted">Conectando ao Macuco Pai...</p><p class="muted">Clique em uma tela para dar foco ao mouse/teclado. Pare o bot da conta antes de comandar manualmente. A transmissão não tem limite fixo de FPS; depende da conexão e do computador.</p><section class="grid" id="grid"></section></main>
<script>
const cards=new Map(),lastFrame=new Map();let socket=null;
const conn=document.getElementById('connection'), grid=document.getElementById('grid');
function send(data){if(socket&&socket.readyState===1)socket.send(JSON.stringify(data))}
function makeCard(slot){let node=document.createElement('article');node.className='card';
 let bar=document.createElement('div');bar.className='cardbar';let title=document.createElement('strong');let state=document.createElement('span');state.className='state';bar.append(title,state);
 let box=document.createElement('div');box.className='preview';box.tabIndex=0;let img=document.createElement('img');img.alt='Tela da VM '+(slot+1);let empty=document.createElement('span');empty.textContent='Aguardando imagem';box.append(img,empty);
 let actions=document.createElement('div');actions.className='actions';let start=document.createElement('button');start.textContent='▶ Iniciar bot';let stop=document.createElement('button');stop.className='secondary';stop.textContent='■ Parar bot';actions.append(start,stop);
 start.onclick=()=>send({type:'action',slot,action:'start'});stop.onclick=()=>send({type:'action',slot,action:'stop'});
 box.addEventListener('click',evt=>{box.focus();if(node.dataset.running==='true')return;let r=img.getBoundingClientRect();if(!img.naturalWidth)return;let scale=Math.min(r.width/img.naturalWidth,r.height/img.naturalHeight);let w=img.naturalWidth*scale,h=img.naturalHeight*scale;let ox=r.left+(r.width-w)/2,oy=r.top+(r.height-h)/2;let x=(evt.clientX-ox)/w,y=(evt.clientY-oy)/h;if(x>=0&&x<=1&&y>=0&&y<=1)send({type:'action',slot,action:'click',x,y})});
 const held=new Set(); const keycode=e=>{if(e.key.length===1){let n=e.key.toUpperCase().charCodeAt(0);if((n>=48&&n<=57)||(n>=65&&n<=90))return n}const m={" ":32,ArrowLeft:37,ArrowUp:38,ArrowRight:39,ArrowDown:40,Enter:13,Escape:27,Space:32,Tab:9,Backspace:8};if(e.key in m)return m[e.key];if(/^F([1-9]|1[0-2])$/.test(e.key))return 111+Number(e.key.slice(1));return null};
 box.addEventListener('keydown',e=>{const k=keycode(e);if(k===null||node.dataset.running==='true')return;e.preventDefault();if(!held.has(k)){held.add(k);send({type:'action',slot,action:'key',key:k,pressed:true})}});
 box.addEventListener('keyup',e=>{const k=keycode(e);if(k===null)return;e.preventDefault();if(held.has(k)){held.delete(k);send({type:'action',slot,action:'key',key:k,pressed:false})}});
 box.addEventListener('blur',()=>{for(let k of held)send({type:'action',slot,action:'key',key:k,pressed:false});held.clear()});
 node.append(bar,box,actions);grid.append(node);cards.set(slot,{node,title,state,img,empty});return cards.get(slot)
}
function show(data){if(data.type==='status'){conn.textContent=data.online?'Macuco Pai conectado':'Macuco Pai desconectado';const allowed=new Set(data.accounts.map(a=>a.slot));for(const [slot,c] of cards){if(!allowed.has(slot))c.node.remove(),cards.delete(slot)}for(const a of data.accounts){let c=cards.get(a.slot)||makeCard(a.slot);c.title.textContent=a.name||'Conta '+(a.slot+1);c.state.textContent=a.status||'';c.node.dataset.running=!!a.running;}}else if(data.type==='frame'){
 let c=cards.get(data.slot);if(!c)return;if((lastFrame.get(data.slot)||0)>=data.ts)return;lastFrame.set(data.slot,data.ts);c.img.src='data:image/jpeg;base64,'+data.jpg;c.empty.className='hidden';}}
function connect(){socket=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host+'/ws/viewer');socket.onopen=()=>{conn.textContent='Conectado ao servidor. Aguardando Macuco Pai...'};socket.onmessage=e=>{try{show(JSON.parse(e.data))}catch(err){console.error(err)}};socket.onclose=()=>{conn.textContent='Servidor desconectado; tentando novamente';setTimeout(connect,1500)}}connect();
</script>'''

def create_app(data_dir: Path):
    data_dir=Path(data_dir)
    cfg=json.loads((data_dir/'server_config.json').read_text(encoding='utf8'))
    if len(cfg.get('host_token','')) < 40:
        raise RuntimeError('Host token ausente/inseguro. Execute configurar.py.')
    db=data_dir/'macuco_accounts.db'
    app=FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    relay=Relay()
    app.state.relay=relay
    login_attempts={}
    secure_cookies=bool(cfg.get('secure_cookies',False))
    def current(request):
        with dbconnect(db) as con:return session_for(con,request.cookies.get('macuco_sid'))
    @app.get('/')
    async def root(request:Request):
        s=current(request)
        if not s:return RedirectResponse('/login',303)
        return RedirectResponse('/change-password' if s['must_change'] else '/dashboard',303)
    @app.get('/login')
    async def login_get(request:Request):
        if current(request):return RedirectResponse('/',303)
        return login_page()
    @app.post('/login')
    async def login_post(request:Request):
        ip=request.client.host if request.client else 'unknown'
        recent=[v for v in login_attempts.get(ip,[]) if time.monotonic()-v<300]
        if len(recent)>=12:
            return login_page('Tentativas demais. Aguarde cinco minutos.')
        form=await request.form()
        user=str(form.get('username',''))[:80]
        password=str(form.get('password',''))
        with dbconnect(db) as con:
            row=con.execute('SELECT * FROM users WHERE username=?',(user,)).fetchone()
            valid=bool(row and hmac.compare_digest(password_hash(password,row['salt']),row['passhash']))
            if not valid:
                recent.append(time.monotonic());login_attempts[ip]=recent
                return login_page('Usuario ou senha incorretos.')
            login_attempts.pop(ip,None)
            sid=secrets.token_urlsafe(32)
            con.execute('INSERT INTO sessions VALUES (?,?,?,?)',(hashlib.sha256(sid.encode()).hexdigest(),user,secrets.token_urlsafe(24),int(time.time())+SESS_AGE))
        response=RedirectResponse('/change-password' if row['must_change'] else '/dashboard',303)
        response.set_cookie('macuco_sid',sid,max_age=SESS_AGE,secure=(secure_cookies or request.url.scheme=='https'),httponly=True,samesite='strict',path='/')
        return response
    @app.get('/change-password')
    async def change_get(request:Request):
        s=current(request)
        if not s:return RedirectResponse('/login',303)
        return csrf_page(s['csrf'])
    @app.post('/change-password')
    async def change_post(request:Request):
        s=current(request)
        if not s:return RedirectResponse('/login',303)
        form=await request.form()
        old=str(form.get('old','')); new=str(form.get('new',''))
        if not hmac.compare_digest(str(form.get('csrf','')),s['csrf']):return PlainTextResponse('CSRF invalido',403)
        with dbconnect(db) as con:
            row=con.execute('SELECT * FROM users WHERE username=?',(s['username'],)).fetchone()
            if not hmac.compare_digest(password_hash(old,row['salt']),row['passhash']):return csrf_page(s['csrf'],'Senha atual incorreta.')
            if len(new)<12 or new=='admin1' or new==old:return csrf_page(s['csrf'],'Use senha nova com ao menos 12 caracteres.')
            salt=os.urandom(16)
            con.execute('UPDATE users SET salt=?,passhash=?,must_change=0 WHERE username=?',(salt,password_hash(new,salt),s['username']))
            # Other sessions logged in with the initial password are revoked.
            con.execute('DELETE FROM sessions WHERE username=? AND token_hash!=?',(s['username'],s['token_hash']))
        return RedirectResponse('/dashboard',303)
    @app.get('/dashboard')
    async def dashboard(request:Request):
        s=current(request)
        if not s:return RedirectResponse('/login',303)
        if s['must_change']:return RedirectResponse('/change-password',303)
        return page('Central Macuco',DASHBOARD.replace('CSRF_PLACEHOLDER',html.escape(s['csrf'])))
    @app.post('/logout')
    async def logout(request:Request):
        s=current(request)
        if s:
            form=await request.form()
            if not hmac.compare_digest(str(form.get('csrf','')),s['csrf']):return PlainTextResponse('CSRF invalido',403)
            with dbconnect(db) as con:con.execute('DELETE FROM sessions WHERE token_hash=?',(s['token_hash'],))
        response=RedirectResponse('/login',303)
        response.delete_cookie('macuco_sid',path='/')
        return response
    async def ws_origin_ok(ws):
        origin=ws.headers.get('origin','')
        if not origin:return False
        return urlparse(origin).netloc.lower()==ws.headers.get('host','').lower()
    @app.websocket('/ws/agent')
    async def agent(ws:WebSocket):
        header=ws.headers.get('authorization','')
        if not header.startswith('Bearer ') or not hmac.compare_digest(header[7:],cfg['host_token']):
            await ws.close(code=1008);return
        if relay.agent is not None:
            await ws.close(code=1008);return
        await ws.accept()
        relay.agent=ws
        relay.allowed_slots=set()
        try:
            while True:
                raw=await ws.receive_text()
                if len(raw)>3_000_000:continue
                try:msg=json.loads(raw)
                except (ValueError,TypeError):continue
                if not isinstance(msg,dict):continue
                if msg.get('type')=='status':
                    accounts=msg.get('accounts',[])
                    if not isinstance(accounts,list):continue
                    sanitized=[]
                    for acc in accounts[:10]:
                        if (isinstance(acc,dict) and type(acc.get('slot')) is int and 0<=acc['slot']<10):
                            sanitized.append({'slot':acc['slot'],'name':str(acc.get('name',''))[:80], 'status':str(acc.get('status',''))[:120], 'running':bool(acc.get('running'))})
                    relay.allowed_slots={a['slot'] for a in sanitized}
                    relay.metadata=sanitized
                    await relay.announce({'type':'status','online':True,'accounts':sanitized})
                elif msg.get('type')=='frame':
                    slot=msg.get('slot');jpg=msg.get('jpg','')
                    if type(slot) is int and slot in relay.allowed_slots and isinstance(jpg,str) and len(jpg)<2_000_000:
                        await relay.announce({'type':'frame','slot':slot,'ts':msg.get('ts'), 'jpg':jpg})
        except (WebSocketDisconnect,RuntimeError):pass
        finally:
            if relay.agent is ws:
                relay.agent=None;relay.allowed_slots.clear();relay.metadata=[]
                await relay.announce({'type':'status','online':False,'accounts':[]})
    @app.websocket('/ws/viewer')
    async def viewer(ws:WebSocket):
        if not await ws_origin_ok(ws):await ws.close(code=1008);return
        with dbconnect(db) as con:s=session_for(con,ws.cookies.get('macuco_sid'))
        if s is None or s['must_change']:await ws.close(code=1008);return
        await ws.accept()
        q=asyncio.Queue(maxsize=50)
        relay.viewers.add(q)
        await q.put(json.dumps({'type':'status','online':relay.agent is not None,'accounts':relay.metadata}))
        async def sender():
            while True:await ws.send_text(await q.get())
        task=asyncio.create_task(sender())
        try:
            while True:
                raw=await ws.receive_text()
                if len(raw)>1500:continue
                try:m=json.loads(raw)
                except (ValueError,TypeError):continue
                if not isinstance(m,dict) or m.get('type')!='action':continue
                slot=m.get('slot');action=m.get('action')
                if type(slot) is not int or slot not in relay.allowed_slots or action not in ('start','stop','click','key'):continue
                obj={'type':'action','slot':slot,'action':action}
                if action=='click':
                    x,y=m.get('x'),m.get('y')
                    if type(x) not in (int,float) or type(y) not in (int,float) or not (0<=x<=1 and 0<=y<=1):continue
                    obj.update(x=x,y=y)
                if action=='key':
                    k,pressed=m.get('key'),m.get('pressed')
                    if type(k) is not int or k not in VALID_KEYS or type(pressed) is not bool:continue
                    obj.update(key=k,pressed=pressed)
                await relay.send_agent(obj)
        except (WebSocketDisconnect,RuntimeError):pass
        finally:
            task.cancel();relay.viewers.discard(q)
    return app

def default_data_dir():
    requested=os.getenv('MACUCO_SERVER_DIR')
    if requested:return Path(requested)
    if os.name=='nt':
        root=Path(os.getenv('LOCALAPPDATA',Path.home()))
    else:
        root=Path.home()/'.local'/'share'
    return root/'ControleMacuco'/'site'

BASE=default_data_dir()
if (BASE/'server_config.json').exists():
    app=create_app(BASE)
else:
    app=FastAPI()
    @app.get('/')
    def unconfigured():return PlainTextResponse('Servidor nao configurado. Execute: python configurar.py',status_code=503)
