import sys, struct, socket

BASE=0x08040000
SIZE=0x00100000  # 1MB flat memory
mem=bytearray(SIZE)

def load():
    d=open('/home/claude/gt','rb').read()
    # program header: offset 0x60 -> vaddr 0x8048060, filesz 0xf23, memsz 0xfd8
    vaddr=0x8048060; foff=0x60; filesz=0xf23
    mem[vaddr-BASE:vaddr-BASE+filesz]=d[foff:foff+filesz]

load()

def rd(addr,n): return mem[addr-BASE:addr-BASE+n]
def wr(addr,data): mem[addr-BASE:addr-BASE+len(data)]=data
def u8(a): return mem[a-BASE]
def u16(a): return struct.unpack('<H', rd(a,2))[0]
def u32(a): return struct.unpack('<I', rd(a,4))[0]
def w8(a,v): mem[a-BASE]=v&0xff
def w16(a,v): wr(a, struct.pack('<H', v&0xffff))
def w32(a,v): wr(a, struct.pack('<I', v&0xffffffff))

REGS=['eax','ecx','edx','ebx','esp','ebp','esi','edi']
regs={r:0 for r in REGS}
flags={'ZF':0,'SF':0,'CF':0,'OF':0}

STACK_TOP = BASE+SIZE-0x1000
regs['esp']=STACK_TOP
regs['ebp']=STACK_TOP

def push32(v):
    regs['esp']=(regs['esp']-4)&0xffffffff
    w32(regs['esp'], v&0xffffffff)
def pop32():
    v=u32(regs['esp'])
    regs['esp']=(regs['esp']+4)&0xffffffff
    return v

def setflags_sub(a,b,res,size=32):
    mask=(1<<size)-1
    flags['ZF']= 1 if (res&mask)==0 else 0
    flags['SF']= 1 if (res>>(size-1))&1 else 0
    flags['CF']= 1 if (a&mask) < (b&mask) else 0
    sa=1 if (a>>(size-1))&1 else 0
    sb=1 if (b>>(size-1))&1 else 0
    sr=1 if (res>>(size-1))&1 else 0
    flags['OF']= 1 if (sa!=sb and sr!=sa) else 0

def setflags_logic(res,size=32):
    mask=(1<<size)-1
    flags['ZF']=1 if (res&mask)==0 else 0
    flags['SF']=1 if (res>>(size-1))&1 else 0
    flags['CF']=0; flags['OF']=0

RIP=[0x8048060]

def fetch8():
    v=u8(RIP[0]); RIP[0]+=1; return v
def fetch16():
    v=u16(RIP[0]); RIP[0]+=2; return v
def fetch32():
    v=u32(RIP[0]); RIP[0]+=4; return v
def fetchs8():
    v=fetch8()
    return v-256 if v>=128 else v
def fetchs32():
    v=fetch32()
    return v-0x100000000 if v>=0x80000000 else v

def regname32(n): return REGS[n]
def regname16(n): return ['ax','cx','dx','bx','sp','bp','si','di'][n]
def regname8(n): return ['al','cl','dl','bl','ah','ch','dh','bh'][n]

def get_reg(n,size):
    if size==32: return regs[REGS[n]]
    if size==16: return regs[REGS[n]]&0xffff
    if size==8:
        if n<4: return regs[REGS[n]]&0xff
        else: return (regs[REGS[n-4]]>>8)&0xff
def set_reg(n,size,val):
    if size==32: regs[REGS[n]]=val&0xffffffff
    elif size==16: regs[REGS[n]]=(regs[REGS[n]]&0xffff0000)|(val&0xffff)
    elif size==8:
        if n<4: regs[REGS[n]]=(regs[REGS[n]]&0xffffff00)|(val&0xff)
        else: regs[REGS[n-4]]=(regs[REGS[n-4]]&0xffff00ff)|((val&0xff)<<8)

class MemOperand:
    def __init__(self,addr): self.addr=addr
    def get(self,size):
        if size==32: return u32(self.addr)
        if size==16: return u16(self.addr)
        if size==8: return u8(self.addr)
    def set(self,size,val):
        if size==32: w32(self.addr,val)
        elif size==16: w16(self.addr,val)
        elif size==8: w8(self.addr,val)

def decode_modrm(size):
    """Decode ModRM(+SIB+disp) at RIP. Return (is_reg, reg_field, operand) where operand supports get(size)/set(size,val) or is an int reg index if is_reg."""
    modrm=fetch8()
    mod=(modrm>>6)&3; reg=(modrm>>3)&7; rm=modrm&7
    if mod==3:
        return True, reg, rm  # rm is reg index
    # memory operand
    base=None; idx=None; scale=1; disp=0
    if rm==4:
        sib=fetch8()
        scale=1<<((sib>>6)&3); idx=(sib>>3)&7; base=sib&7
        if idx==4: idx=None
        if mod==0 and base==5:
            disp=fetchs32(); base=None
        else:
            base=REGS[base]
    elif mod==0 and rm==5:
        disp=fetchs32()
        base=None
    else:
        base=REGS[rm]
    if mod==1:
        disp=fetchs8()
    elif mod==2:
        disp=fetchs32()
    addr=0
    if base is not None: addr+=regs[base]
    if idx is not None: addr+=regs[REGS[idx]]*scale
    addr=(addr+disp)&0xffffffff
    return False, reg, MemOperand(addr)

def rm_get(is_reg,rm,size):
    if is_reg: return get_reg(rm,size)
    return rm.get(size)
def rm_set(is_reg,rm,size,val):
    if is_reg: set_reg(rm,size,val)
    else: rm.set(size,val)

SYSCALL_NAMES={1:'exit',2:'fork',3:'read',4:'write',5:'open',6:'close',10:'unlink',24:'getuid',26:'ptrace',44:'prof',45:'brk',46:'setgid',70:'setreuid',
 67:'sigaction',92:'truncate',119:'sigreturn',120:'clone',122:'uname',128:'init_module',162:'nanosleep',
 164:'setresuid',190:'vfork',252:'exit_group',359:'socket',360:'socketpair',361:'bind',362:'connect',
 363:'listen',364:'accept4',365:'getsockopt',366:'setsockopt',367:'getsockname',368:'getpeername',
 369:'sendto',370:'sendmsg',371:'recvfrom',372:'recvmsg',373:'shutdown'}

STDIN_DATA=[b'']  # set externally
STDOUT=[b'']
open_files={}
fake_fd_ctr=[100]
sockets={}

ORACLE_HOST='127.0.0.1'
ORACLE_PORT=1337
FAKE_ORACLE_RESPONSE=[None]  # set externally to bytes

def do_syscall():
    nr=regs['eax']
    name=SYSCALL_NAMES.get(nr,'unk%d'%nr)
    ebx,ecx,edx=regs['ebx'],regs['ecx'],regs['edx']
    ret=0
    if name=='ptrace':
        ret=0
    elif name=='uname':
        ret=0
    elif name=='prof':
        ret=0
    elif name=='truncate':
        ret=0
    elif name=='sigaction':
        ret=0
    elif name=='vfork' or name=='fork':
        ret=0  # we are the child
    elif name=='setresuid':
        ret=0
    elif name=='socket':
        fd=fake_fd_ctr[0]; fake_fd_ctr[0]+=1
        sockets[fd]={'connected':False}
        ret=fd
    elif name=='connect':
        data=rd(ecx,16)
        fam,port=struct.unpack('<HH',data[:4])
        port=socket.htons(port)
        addr='.'.join(str(b) for b in data[4:8])
        print('[connect] fd=%d -> %s:%d'%(ebx,addr,port))
        sockets.setdefault(ebx,{})['connected']=True
        sockets[ebx]['peer']=(addr,port)
        ret=0
    elif name=='bind':
        ret=0
    elif name=='listen':
        ret=0
    elif name=='read':
        if ebx==0:
            data=STDIN_DATA[0][:edx]
            STDIN_DATA[0]=STDIN_DATA[0][len(data):]
            wr(ecx,data)
            ret=len(data)
        else:
            ret=0
    elif name=='write':
        data=bytes(rd(ecx,edx))
        if ebx==1 or ebx==2:
            STDOUT[0]+=data
            sys.stdout.write(data.decode('latin1'))
            sys.stdout.flush()
        ret=len(data)
    elif name=='open':
        # read cstring at ebx
        a=ebx; s=b''
        while True:
            c=u8(a)
            if c==0: break
            s+=bytes([c]); a+=1
        print('[open] "%s" flags=%d'%(s.decode('latin1'),ecx))
        fd=fake_fd_ctr[0]; fake_fd_ctr[0]+=1
        open_files[fd]={'name':s,'pos':0}
        ret=fd
    elif name=='close':
        ret=0
    elif name in ('send','sendto'):
        data=bytes(rd(ecx,edx))
        print('[send] fd=%d data=%r'%(ebx,data))
        ret=len(data)
    elif name in ('recv','recvfrom'):
        resp=FAKE_ORACLE_RESPONSE[0] or b''
        n=min(edx,len(resp))
        wr(ecx,resp[:n])
        print('[recv] fd=%d got %d bytes: %r'%(ebx,n,resp[:n]))
        ret=n
    elif name=='exit' or name=='exit_group':
        print('[exit] code=%d'%ebx)
        raise SystemExit(ebx)
    elif name=='brk':
        ret=ebx if ebx else 0x08060000
    else:
        print('[syscall] UNIMPLEMENTED', name, nr, hex(ebx),hex(ecx),hex(edx))
        ret=0
    regs['eax']=ret&0xffffffff

STOP=[False]
CMPS_HOOK=[None]

def step():
    start=RIP[0]
    op=fetch8()
    # prefixes
    opsize=32
    rep=None
    while op in (0x66,0xf3,0xf2,0x2e,0x3e,0x26,0x64,0x65,0x36):
        if op==0x66: opsize=16
        if op in (0xf3,0xf2): rep=op
        op=fetch8()
    if rep is not None and op in (0xa4,0xa5,0xaa,0xab,0xa6,0xa7):
        while regs['ecx']!=0:
            execute_one(op,opsize)
            regs['ecx']=(regs['ecx']-1)&0xffffffff
            if rep==0xf2 and op in (0xa6,0xa7) and flags['ZF']==1: break
            if rep==0xf3 and op in (0xa6,0xa7) and flags['ZF']==0: break
        return True
    return execute_one(op,opsize)

def execute_one(op,opsize):
    if 0xb8<=op<=0xbf:
        n=op-0xb8
        if opsize==32: v=fetch32()
        else: v=fetch16()
        set_reg(n,opsize,v)
    elif op==0x31: # xor r/m, r32
        is_reg,reg,rm=decode_modrm(opsize)
        a=rm_get(is_reg,rm,opsize); b=get_reg(reg,opsize)
        res=a^b
        rm_set(is_reg,rm,opsize,res); setflags_logic(res,opsize)
    elif op==0x29: # sub r/m,r32
        is_reg,reg,rm=decode_modrm(opsize)
        a=rm_get(is_reg,rm,opsize); b=get_reg(reg,opsize)
        res=a-b
        rm_set(is_reg,rm,opsize,res&((1<<opsize)-1)); setflags_sub(a,b,res,opsize)
    elif op==0x01: # add r/m,r32
        is_reg,reg,rm=decode_modrm(opsize)
        a=rm_get(is_reg,rm,opsize); b=get_reg(reg,opsize)
        res=a+b
        rm_set(is_reg,rm,opsize,res&((1<<opsize)-1))
        flags['ZF']=1 if (res&((1<<opsize)-1))==0 else 0
    elif op==0x09: # or r/m,r32
        is_reg,reg,rm=decode_modrm(opsize)
        a=rm_get(is_reg,rm,opsize); b=get_reg(reg,opsize)
        res=a|b
        rm_set(is_reg,rm,opsize,res); setflags_logic(res,opsize)
    elif op==0x21: # and r/m,r32
        is_reg,reg,rm=decode_modrm(opsize)
        a=rm_get(is_reg,rm,opsize); b=get_reg(reg,opsize)
        res=a&b
        rm_set(is_reg,rm,opsize,res); setflags_logic(res,opsize)
    elif op==0x89: # mov r/m,r32
        is_reg,reg,rm=decode_modrm(opsize)
        rm_set(is_reg,rm,opsize,get_reg(reg,opsize))
    elif op==0x8b: # mov r32,r/m
        is_reg,reg,rm=decode_modrm(opsize)
        set_reg(reg,opsize,rm_get(is_reg,rm,opsize))
    elif op==0x8d: # lea
        is_reg,reg,rm=decode_modrm(opsize)
        set_reg(reg,opsize,rm.addr)
    elif op==0x83: # grp1 r/m, imm8
        is_reg,regf,rm=decode_modrm(opsize)
        imm=fetchs8()&((1<<opsize)-1)
        a=rm_get(is_reg,rm,opsize)
        if regf==0: res=a+imm; rm_set(is_reg,rm,opsize,res&((1<<opsize)-1)); flags['ZF']=1 if (res&((1<<opsize)-1))==0 else 0
        elif regf==5: res=a-imm; rm_set(is_reg,rm,opsize,res&((1<<opsize)-1)); setflags_sub(a,imm,res,opsize)
        elif regf==7: res=a-imm; setflags_sub(a,imm,res,opsize)
        elif regf==4: res=a&imm; rm_set(is_reg,rm,opsize,res); setflags_logic(res,opsize)
        elif regf==1: res=a|imm; rm_set(is_reg,rm,opsize,res); setflags_logic(res,opsize)
        elif regf==6: res=a^imm; rm_set(is_reg,rm,opsize,res); setflags_logic(res,opsize)
        else: raise Exception('83 /%d not impl'%regf)
    elif op==0x81:
        is_reg,regf,rm=decode_modrm(opsize)
        imm=fetch32() if opsize==32 else fetch16()
        a=rm_get(is_reg,rm,opsize)
        if regf==7: res=a-imm; setflags_sub(a,imm,res,opsize)
        elif regf==0: res=a+imm; rm_set(is_reg,rm,opsize,res&((1<<opsize)-1))
        elif regf==5: res=a-imm; rm_set(is_reg,rm,opsize,res&((1<<opsize)-1)); setflags_sub(a,imm,res,opsize)
        elif regf==4: res=a&imm; rm_set(is_reg,rm,opsize,res); setflags_logic(res,opsize)
        else: raise Exception('81 /%d not impl'%regf)
    elif op in (0x04,0x0c,0x14,0x1c,0x24,0x2c,0x34,0x3c): # AL, imm8 group
        imm=fetch8(); a=get_reg(0,8)
        grp=op>>3
        if grp==0: res=a+imm; set_reg(0,8,res&0xff)
        elif grp==1: res=a|imm; set_reg(0,8,res); setflags_logic(res,8)
        elif grp==3: res=a-imm; set_reg(0,8,res&0xff); setflags_sub(a,imm,res,8)
        elif grp==4: res=a&imm; set_reg(0,8,res); setflags_logic(res,8)
        elif grp==5: res=a-imm; set_reg(0,8,res&0xff); setflags_sub(a,imm,res,8)
        elif grp==6: res=a^imm; set_reg(0,8,res); setflags_logic(res,8)
        elif grp==7: res=a-imm; setflags_sub(a,imm,res,8)
    elif op in (0x05,0x0d,0x15,0x1d,0x25,0x2d,0x35,0x3d): # eAX, imm32/16 group
        imm=fetch32() if opsize==32 else fetch16()
        a=get_reg(0,opsize)
        grp=op>>3
        if grp==0: res=a+imm; set_reg(0,opsize,res&((1<<opsize)-1))
        elif grp==1: res=a|imm; set_reg(0,opsize,res); setflags_logic(res,opsize)
        elif grp==3: res=a-imm; set_reg(0,opsize,res&((1<<opsize)-1)); setflags_sub(a,imm,res,opsize)
        elif grp==4: res=a&imm; set_reg(0,opsize,res); setflags_logic(res,opsize)
        elif grp==5: res=a-imm; set_reg(0,opsize,res&((1<<opsize)-1)); setflags_sub(a,imm,res,opsize)
        elif grp==6: res=a^imm; set_reg(0,opsize,res); setflags_logic(res,opsize)
        elif grp==7: res=a-imm; setflags_sub(a,imm,res,opsize)
    elif op==0x3d: # cmp eax,imm32
        imm=fetch32() if opsize==32 else fetch16()
        a=get_reg(0,opsize); res=a-imm; setflags_sub(a,imm,res,opsize)
    elif op==0x39: # cmp r/m,r
        is_reg,reg,rm=decode_modrm(opsize)
        a=rm_get(is_reg,rm,opsize); b=get_reg(reg,opsize); res=a-b; setflags_sub(a,b,res,opsize)
    elif op==0x3b:
        is_reg,reg,rm=decode_modrm(opsize)
        a=get_reg(reg,opsize); b=rm_get(is_reg,rm,opsize); res=a-b; setflags_sub(a,b,res,opsize)
    elif op==0x85: # test r/m,r
        is_reg,reg,rm=decode_modrm(opsize)
        a=rm_get(is_reg,rm,opsize); b=get_reg(reg,opsize); res=a&b; setflags_logic(res,opsize)
    elif op==0xeb:
        d=fetchs8(); RIP[0]+=d
    elif op==0xe9:
        d=fetchs32(); RIP[0]+=d
    elif 0x70<=op<=0x7f:
        d=fetchs8()
        cond=op&0xf
        taken=check_cond(cond)
        if taken: RIP[0]+=d
    elif op==0x0f:
        op2=fetch8()
        if 0x80<=op2<=0x8f:
            d=fetchs32(); cond=op2&0xf
            if check_cond(cond): RIP[0]+=d
        elif op2==0xb6: # movzx r,r/m8
            is_reg,reg,rm=decode_modrm(8)
            v=rm_get(is_reg,rm,8)
            set_reg(reg,32,v)
        elif op2==0xb7:
            is_reg,reg,rm=decode_modrm(16)
            v=rm_get(is_reg,rm,16)
            set_reg(reg,32,v)
        else:
            raise Exception('0f %02x not impl at RIP=%#x'%(op2,RIP[0]))
    elif op==0xe8:
        d=fetchs32()
        ret=RIP[0]
        push32(ret)
        RIP[0]+=d
    elif op==0xc3:
        RIP[0]=pop32()
    elif op==0xc2:
        imm=fetch16()
        RIP[0]=pop32()
        regs['esp']=(regs['esp']+imm)&0xffffffff
    elif 0x50<=op<=0x57:
        push32(regs[REGS[op-0x50]])
    elif 0x58<=op<=0x5f:
        regs[REGS[op-0x58]]=pop32()
    elif op==0x68:
        v=fetch32(); push32(v)
    elif op==0x6a:
        v=fetchs8(); push32(v&0xffffffff)
    elif op==0xa3:
        addr=fetch32(); w32(addr,regs['eax'])
    elif op==0xa1:
        addr=fetch32(); regs['eax']=u32(addr)
    elif op==0xab: # stos (word or dword depending on opsize)
        if opsize==16:
            w16(regs['edi'],regs['eax']&0xffff); regs['edi']=(regs['edi']+2)&0xffffffff
        else:
            w32(regs['edi'],regs['eax']); regs['edi']=(regs['edi']+4)&0xffffffff
    elif op==0xaa: # stosb
        w8(regs['edi'],regs['eax']&0xff); regs['edi']=(regs['edi']+1)&0xffffffff
    elif op==0xa4: # movsb
        w8(regs['edi'],u8(regs['esi'])); regs['esi']=(regs['esi']+1)&0xffffffff; regs['edi']=(regs['edi']+1)&0xffffffff
    elif op==0xa5: # movs (word or dword)
        if opsize==16:
            w16(regs['edi'],u16(regs['esi'])); regs['esi']=(regs['esi']+2)&0xffffffff; regs['edi']=(regs['edi']+2)&0xffffffff
        else:
            w32(regs['edi'],u32(regs['esi'])); regs['esi']=(regs['esi']+4)&0xffffffff; regs['edi']=(regs['edi']+4)&0xffffffff
    elif op==0xa6: # cmpsb
        va=u8(regs['esi']); vb=u8(regs['edi'])
        if CMPS_HOOK[0]: CMPS_HOOK[0](regs['esi'],regs['edi'],va,vb)
        res=va-vb; setflags_sub(va,vb,res,8)
        regs['esi']=(regs['esi']+1)&0xffffffff; regs['edi']=(regs['edi']+1)&0xffffffff
    elif op==0xcd:
        intno=fetch8()
        if intno==0x80: do_syscall()
        else: raise Exception('int %x not impl'%intno)
    elif op==0x90:
        pass
    elif op==0xe2: # loop
        d=fetchs8()
        regs['ecx']=(regs['ecx']-1)&0xffffffff
        if regs['ecx']!=0: RIP[0]+=d
    elif op==0x40<=op<=0x47 if False else False:
        pass
    elif 0x40<=op<=0x47:
        n=op-0x40; regs[REGS[n]]=(regs[REGS[n]]+1)&0xffffffff
    elif 0x48<=op<=0x4f:
        n=op-0x48; regs[REGS[n]]=(regs[REGS[n]]-1)&0xffffffff
    elif op==0xf7:
        is_reg,regf,rm=decode_modrm(opsize)
        if regf==3: # neg
            a=rm_get(is_reg,rm,opsize); res=(-a)&((1<<opsize)-1); rm_set(is_reg,rm,opsize,res)
        elif regf==2: # not
            a=rm_get(is_reg,rm,opsize); res=(~a)&((1<<opsize)-1); rm_set(is_reg,rm,opsize,res)
        elif regf==4: # mul
            a=rm_get(is_reg,rm,opsize); res=regs['eax']*a; regs['eax']=res&0xffffffff; regs['edx']=(res>>32)&0xffffffff
        elif regf==6: # div
            a=rm_get(is_reg,rm,opsize)
            full=(regs['edx']<<32)|regs['eax']
            regs['eax']=(full//a)&0xffffffff; regs['edx']=(full%a)&0xffffffff
        elif regf==7: # idiv
            a=rm_get(is_reg,rm,opsize)
            full=(regs['edx']<<32)|regs['eax']
            if full>=0x8000000000000000: full-=0x10000000000000000
            if a>=0x80000000: a-=0x100000000
            q=int(full/a); r=full - q*a
            regs['eax']=q&0xffffffff; regs['edx']=r&0xffffffff
        elif regf==0: # test imm
            imm=fetch32()
            a=rm_get(is_reg,rm,opsize); res=a&imm; setflags_logic(res,opsize)
        else:
            raise Exception('f7 /%d not impl'%regf)
    elif op==0xff:
        is_reg,regf,rm=decode_modrm(opsize)
        if regf==0:
            a=rm_get(is_reg,rm,opsize); res=(a+1)&((1<<opsize)-1); rm_set(is_reg,rm,opsize,res)
        elif regf==1:
            a=rm_get(is_reg,rm,opsize); res=(a-1)&((1<<opsize)-1); rm_set(is_reg,rm,opsize,res)
        elif regf==2: # call r/m
            a=rm_get(is_reg,rm,32); push32(RIP[0]); RIP[0]=a
        elif regf==4: # jmp r/m
            a=rm_get(is_reg,rm,32); RIP[0]=a
        elif regf==6: # push r/m
            a=rm_get(is_reg,rm,32); push32(a)
        else:
            raise Exception('ff /%d not impl'%regf)
    elif op==0xc7: # mov r/m, imm32/16
        is_reg,regf,rm=decode_modrm(opsize)
        imm = fetch32() if opsize==32 else fetch16()
        rm_set(is_reg,rm,opsize,imm)
    elif op==0xc6:
        is_reg,regf,rm=decode_modrm(8)
        imm=fetch8()
        rm_set(is_reg,rm,8,imm)
    elif op==0x88:
        is_reg,reg,rm=decode_modrm(8)
        rm_set(is_reg,rm,8,get_reg(reg,8))
    elif op==0x8a:
        is_reg,reg,rm=decode_modrm(8)
        set_reg(reg,8,rm_get(is_reg,rm,8))
    elif op==0x00:
        is_reg,reg,rm=decode_modrm(8)
        a=rm_get(is_reg,rm,8); b=get_reg(reg,8); res=a+b; rm_set(is_reg,rm,8,res&0xff)
    elif op==0x28:
        is_reg,reg,rm=decode_modrm(8)
        a=rm_get(is_reg,rm,8); b=get_reg(reg,8); res=a-b; rm_set(is_reg,rm,8,res&0xff); setflags_sub(a,b,res,8)
    elif op==0x38:
        is_reg,reg,rm=decode_modrm(8)
        a=rm_get(is_reg,rm,8); b=get_reg(reg,8); res=a-b; setflags_sub(a,b,res,8)
    elif op==0x80:
        is_reg,regf,rm=decode_modrm(8)
        imm=fetch8()
        a=rm_get(is_reg,rm,8)
        if regf==7: res=a-imm; setflags_sub(a,imm,res,8)
        elif regf==4: res=a&imm; rm_set(is_reg,rm,8,res); setflags_logic(res,8)
        elif regf==0: res=a+imm; rm_set(is_reg,rm,8,res&0xff)
        elif regf==1: res=a|imm; rm_set(is_reg,rm,8,res); setflags_logic(res,8)
        elif regf==5: res=a-imm; rm_set(is_reg,rm,8,res&0xff); setflags_sub(a,imm,res,8)
        elif regf==6: res=a^imm; rm_set(is_reg,rm,8,res); setflags_logic(res,8)
        else: raise Exception('80 /%d'%regf)
    elif op==0xd1 or op==0xd3 or op==0xc1:
        is_reg,regf,rm=decode_modrm(opsize)
        if op==0xc1: amt=fetch8()
        elif op==0xd1: amt=1
        else: amt=regs['ecx']&0x1f
        a=rm_get(is_reg,rm,opsize)
        if regf==4: res=(a<<amt)&((1<<opsize)-1)  # shl
        elif regf==5: res=(a&((1<<opsize)-1))>>amt  # shr
        elif regf==7:
            sv=a if a<(1<<(opsize-1)) else a-(1<<opsize)
            res=(sv>>amt)&((1<<opsize)-1)
        else: raise Exception('shiftgrp /%d'%regf)
        rm_set(is_reg,rm,opsize,res); setflags_logic(res,opsize)
    elif op==0x69:
        is_reg,reg,rm=decode_modrm(opsize)
        imm=fetch32()
        a=rm_get(is_reg,rm,opsize)
        res=(a*imm)&0xffffffff
        set_reg(reg,opsize,res)
    elif op==0x6b:
        is_reg,reg,rm=decode_modrm(opsize)
        imm=fetchs8()
        a=rm_get(is_reg,rm,opsize)
        res=(a*imm)&0xffffffff
        set_reg(reg,opsize,res)
    else:
        raise Exception('opcode %02x not impl at RIP=%#x'%(op,RIP[0]))
    return True

def check_cond(c):
    ZF,SF,CF,OF=flags['ZF'],flags['SF'],flags['CF'],flags['OF']
    if c==0x0: return OF==1
    if c==0x1: return OF==0
    if c==0x2: return CF==1
    if c==0x3: return CF==0
    if c==0x4: return ZF==1
    if c==0x5: return ZF==0
    if c==0x6: return (CF==1 or ZF==1)
    if c==0x7: return (CF==0 and ZF==0)
    if c==0x8: return SF==1
    if c==0x9: return SF==0
    if c==0xa: return False # PF not tracked
    if c==0xb: return False
    if c==0xc: return SF!=OF
    if c==0xd: return SF==OF
    if c==0xe: return (ZF==1 or SF!=OF)
    if c==0xf: return (ZF==0 and SF==OF)
    return False

def run(max_steps=2000000):
    for i in range(max_steps):
        startaddr=RIP[0]
        try:
            step()
        except SystemExit as e:
            print('Program exited with', e.code)
            return
        except Exception as e:
            print('ERROR at instr start',hex(startaddr),':',e)
            raise
    print('max steps reached, RIP=',hex(RIP[0]))

if __name__=='__main__':
    STDIN_DATA[0]=b'\n'*2000
    FAKE_ORACLE_RESPONSE[0]=b'tribectf{FAKE_FLAG_FOR_TESTING_0000000000}'
    run()
