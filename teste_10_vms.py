"""Integration checks, using FastAPI HTTP+WebSocket (no Windows GUI required)."""
import os,sys,tempfile
from pathlib import Path
from contextlib import ExitStack
from fastapi.testclient import TestClient
from hashlib import sha256
BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(BASE))
os.environ['MACUCO_SERVER_DIR']=tempfile.mkdtemp(prefix='macuco-render-')
os.environ['MACUCO_PUBLIC_DEPLOY']='0'
from servidor_v98 import create_app
APP=create_app(Path(os.environ['MACUCO_SERVER_DIR']))
KEYS=[f'{i:032x}' for i in range(1,12)]
PASS='UmaSenhaSegura!123'
with TestClient(APP) as c:
    resp=c.post('/api/register',json={'username':'foguete','password':PASS})
    assert resp.status_code==200,(resp.status_code,resp.text)
    sid=resp.json()['sid']
    headers={'cookie':'macuco_sid='+sid}
    devs=[]
    for n in range(1,11):
        resp=c.post('/api/devices/bootstrap',json={'client_id':KEYS[n-1],'vm_slot':n},headers=headers)
        assert resp.status_code==200,(n,resp.status_code,resp.text)
        devs.append(resp.json())
    assert len({d['id'] for d in devs})==10
    x=c.get('/api/devices',headers=headers).json()['devices']
    assert [d['vm_slot'] for d in x]==list(range(1,11)),x
    assert len(x)==10
    assert c.post('/api/devices/bootstrap',json={'client_id':KEYS[10],'vm_slot':1},headers=headers).status_code==409
    assert c.post('/api/devices/bootstrap',json={'client_id':KEYS[10],'vm_slot':11},headers=headers).status_code==400
    # Real web sockets via TestClient: ten independent agents live at once.
    with ExitStack() as stack:
        agents=[]
        for dev in devs:
            ws=stack.enter_context(c.websocket_connect('/ws/agent_v98',headers={'Authorization':'Bearer '+dev['token']}))
            ws.send_json({'type':'state','armed':True})
            agents.append(ws)
        # HTTP may race state messages under TestClient tasks, polling.
        import time
        for _ in range(70):
            status=c.get('/api/devices',headers=headers).json()['devices']
            if len(status)==10 and all(d['online'] and d['available'] for d in status):break
            time.sleep(.025)
        assert all(d['online'] and d['available'] for d in status),status
        # Same owner can enter VM 6 without affecting VM 1 or 2.
        with c.websocket_connect('/ws/control/'+devs[5]['id'],headers={**headers,'origin':'http://testserver'}) as viewer:
            # host needs to consume control_begin; TestClient agent sender recv
            msg=agents[5].receive_json()
            assert msg['type']=='control_begin',msg
            agents[5].send_json({'type':'ui_frame','w':40,'h':20,'jpg':'dGVzdA=='})
            # Initial connected/frame may reorder through queue; accept both
            received=[viewer.receive_json() for _ in range(2)]
            assert any(x.get('type')=='ui_frame' for x in received),received
            assert any(x.get('type')=='connected' for x in received),received
            viewer.send_json({'type':'ui_action','action':'click','x':0.5,'y':0.5,'button':'left'})
            msg=agents[5].receive_json()
            assert msg['type']=='ui_action',msg
            agents[5].send_json({'type':'owner_input'})
            rev=viewer.receive_json()
            assert rev['type']=='revoked',rev
            # after owner input, VM 6 can become unavailable but VM 1 unaffected
            status=c.get('/api/devices',headers=headers).json()['devices']
            assert status[0]['available'],status[0]
        # Duplicate token cannot start a second agent for VM1.
        from starlette.websockets import WebSocketDisconnect
        try:
            with c.websocket_connect('/ws/agent_v98',headers={'Authorization':'Bearer '+devs[0]['token']}) as dup:
                dup.receive_json()
            raise AssertionError('duplicate agent accepted')
        except WebSocketDisconnect:
            pass
    # After exiting all host sockets, next start can rotate only its own token.
    resp=c.post('/api/devices/bootstrap',json={'client_id':KEYS[0],'vm_slot':1},headers=headers)
    assert resp.status_code==200,resp.text
    assert resp.json()['id']==devs[0]['id']
    # Database persisted after new app is built.
    new_app=create_app(Path(os.environ['MACUCO_SERVER_DIR']))
    with TestClient(new_app) as nc:
        assert nc.post('/api/login',json={'username':'foguete','password':PASS}).status_code==200
        devices=nc.get('/api/devices',headers=headers).json()['devices']
        assert len(devices)==10,devices
print('PASS: 10 VMs, status, exclusive agent, live WebSockets/frame/control, owner revocation, isolation, persistence')
