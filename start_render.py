"""Render relay; SQLite requires an attached persistent disk at /data."""
import os
from pathlib import Path
import uvicorn
if __name__=='__main__':
    os.environ['MACUCO_PUBLIC_DEPLOY']='1'
    root=Path(os.environ.get('MACUCO_SERVER_DIR','/data'))
    if not root.is_dir() or not os.access(root,os.W_OK):
        raise SystemExit('ERRO: disco persistente nao montado em /data. Configure um Persistent Disk no Render.')
    if os.environ.get('MACUCO_CONFIRM_PERSISTENCE')!='YES':
        raise SystemExit('Configure MACUCO_CONFIRM_PERSISTENCE=YES somente depois de montar o disco persistente.')
    port=int(os.environ.get('PORT','10000'))
    print('Macuco Render: banco no disco persistente',root,flush=True)
    uvicorn.run('servidor_v98:app',host='0.0.0.0',port=port,workers=1,ws_ping_interval=20,ws_ping_timeout=30)
