import sys
import ast
import random
import zlib
import marshal
import base64
import bz2
import re
import hashlib
import itertools
import string
from pystyle import *

if sys.version_info < (3, 10):
    print("Install Python Version = 3.10 or > 3.10 To Use This Code ")
    sys.exit()

def _rd():
    return "".join(__import__("random").sample(
        [chr(i) for i in range(97, 122)], k=8))

def _rd1():
    return "".join(__import__("random").sample(
        [chr(i) for i in range(97, 122)], k=3))

def rd():
    return "_" + "".join(__import__("random").sample([str(i) for i in range(1, 50)], k=4))

def randomint():
    return "".join(__import__("random").sample([str(i) for i in range(1, 50)], k=3))

def generate_malware_payload():
    payload = []
    
    for i in range(25):  
        block_size = random.randint(2000, 8000)
        bytecode = ''.join(random.choices('0123456789abcdef', k=block_size))
        var_name = rd()
        payload.append(f'{var_name}_block = b"{bytecode}"')
    
    for i in range(15):  
        algo_name = rd()
        payload.append(f'''
def {algo_name}_algo(data):
    return {rd()}_xor({rd()}_shift({rd()}_rotate({rd()}_permute({rd()}_transform(data)))))
''')
    
    for i in range(50):  
        struct_name = rd()
        data_size = random.randint(500, 2000)  
        data = [random.randint(0, 255) for _ in range(data_size)]
        payload.append(f'{struct_name}_data = {data}')
    
    for i in range(25):  
        transform_name = rd()
        payload.append(f'''
def {transform_name}_transform(data):
    return {rd()}_encode({rd()}_compress({rd()}_encrypt({rd()}_hash(data))))
''')
    
    for i in range(75): 
        table_name = rd()
        table_size = random.randint(200, 1000)  
        table_data = {rd(): random.randint(0, 255) for _ in range(table_size)}
        payload.append(f'{table_name}_table = {table_data}')
    
    return '\n'.join(payload)

def generate_complex_bytecode():
    bytecode = []
    for i in range(100):
        size = random.randint(500, 2000)
        bytes_data = [random.randint(0, 255) for _ in range(size)]
        var_name = rd()
        bytecode.append(f'{var_name}_bytes = {bytes_data}')
    for i in range(25):
        func_name = rd()
        bytecode.append(f'''
def {func_name}_encode(data):
    return {rd()}_compress({rd()}_encrypt({rd()}_transform(data)))
''')
    
    return '\n'.join(bytecode)

def _chrobf(x):
    return ord(x) + 0xFF78FF

def obfstr(v):
    global _join
    global _hexrun
    global obfint
    if v == "":
        return f"''"
    else:
        x = []
        r = list(v)
        for i in range(len(r)):
            x.append(_chrobf(r[i]))
        _str_ = f"(lambda: (lambda: (lambda: (lambda: {_join}(( {_list}({_map}({_hexrun}, {x})) )))())())())()"
        return _str_

def _byte(v):
    byte_array = bytearray()
    byte_array.extend(v.to_bytes((v.bit_length() + 7) // 8, 'big'))
    return b"obfuscated/" + byte_array

def obfint(v):
    n = rd()
    if 'bool' in str(type(v)):
        if str(v)=='True':
            return f'(lambda: (lambda {n}: {n} + (lambda : hoanggiakietSbF7({(1+0x7777)}))())(0) == 1)()'
        else:
            return f'(lambda: (lambda {n}: {n} - (lambda : hoanggiakietSbF7(({(1+0x7777)} ) ) )())(0) == 1)()'
    else:
        return f'(lambda: c2h6({_byte(int(v))}))()'

def varsobf(v):
    return f"""({(v)}) if bool(bool(bool({(v)}))) < bool(type(int({randomint()})>int({randomint()})<int({randomint()})>int({randomint()}))) and bool(str(str({randomint()})>int({randomint()})<int({randomint()})>int({randomint()}))) > 2 else {v}"""

_join = "lua"
_lambda = "ᅠ"
_int = "nuoc"
_str = "bang"
_bool = "kiet"
_type = "obff"
_bytes = "vang"
_vars = "lobal"
_ip = "go"
ngoac = "{"
_ngoac = "}"
___import__ = "kiethoang"
_movdiv = "hoanggiakiet"
_hexrun = "sad"
_argshexrun = "hoanggiakietso3"
__print = r"tryᅠ"
__input = r"exceptᅠ"
_eval = "banggia"
_list = "quangthang"
_map = "map"

def unicodeobf(x):
    b = []
    for i in x:
        j = ord(i) + 0xFF78FF
        b.append(j)
    return b

def _uni(x):
    return unicodeobf(x)

__bool = rd()
__exx = rd()
_temp = rd()
_temp1 = rd()
_wt = rd()
_exp = rd()

def generate_malware_payload():
    payload = []
    for i in range(100):
        block_size = random.randint(2000, 8000)
        encrypted_data = ''.join(random.choices('0123456789abcdef', k=block_size))
        var_name = rd()
        payload.append(f'{var_name}_encrypted = b"{encrypted_data}"')
    for i in range(50):
        algo_name = rd()
        payload.append(f'''
def {algo_name}_algorithm(data):
    return {rd()}_xor({rd()}_shift({rd()}_rotate({rd()}_permute(data))))
''')
    for i in range(200):
        struct_name = rd()
        data_size = random.randint(1000, 5000)
        data = [random.randint(0, 255) for _ in range(data_size)]
        payload.append(f'{struct_name}_data = {data}')
    for i in range(75):
        transform_name = rd()
        payload.append(f'''
def {transform_name}_transform(data):
    return {rd()}_encode({rd()}_compress({rd()}_encrypt(data)))
''')
    for i in range(150):
        table_name = rd()
        table_size = random.randint(500, 2000)
        table_data = {rd(): random.randint(0, 255) for _ in range(table_size)}
        payload.append(f'{table_name}_table = {table_data}')
    
    return '\n'.join(payload)


var = fr"""
{generate_malware_payload()}
"""
for i in range(200):  
    var += f"""
{i}
{rd()}_key = {random.randint(0, 255)}
{rd()}_iv = {[random.randint(0, 255) for _ in range(8)]}   
{rd()}_salt = b"{''.join(random.choices('0123456789abcdef', k=16))}" 
{rd()}_hash = {random.randint(0, 0xFFFFFFFF)}
"""

var += fr"""

globals()['{_bool}'] = {varsobf('bool')}
globals()['{_str}'] =  {varsobf('str')}
globals()['{_type}'] =  {varsobf('type')}
globals()['{_int}'] =  {varsobf('int')}
globals()['{_bytes}'] =  {varsobf('bytes')}
globals()['{_vars}'] =  {varsobf('vars')}
globals()['{_movdiv}'] =  {varsobf('callable')}
globals()['{_eval}'] =  {varsobf('eval')}
globals()['{_list}'] =  {varsobf('list')}
globals()['{_map}'] =  {varsobf('map')}

globals()['{___import__}'] =  {varsobf('__import__')}

globals()['tryᅠ'] =  {varsobf('print')}
globals()['exceptᅠ'] =  {varsobf('input')}

def {_join}(giakiethoang,*k):
    if k:
        obfuscated= '+'
        op = "+"
    else:
        obfuscated= ''
        op = ''
    globals()['{__exx}'] = {obfint(True)}
    globals()['{_join}'] = {_join}
    globals()['{_str}'] = {_str}
    globals()['giakiethoang'] = giakiethoang
    for globals()['obfuscated_'] in globals()['giakiethoang']:
        if not {__exx}:globals()['obfuscated_'] += (lambda : '')()
        obfuscated+= {_str}(obfuscated_);f = {obfint(True)}
    return obfuscated

def hoanggiakietSbF7(x):
    return {_int}(x-0x7777)

def c2h6(e):
    br = bytearray(e[len(b"obfuscated/"):])
    r = 0
    for b in br:
        r = r * 256 + b
    return r

def longlongint(x):
    ar = []
    for i in x:
        ar.append({_eval}(i))
    return ar

if {obfint(True)}:
    def {_hexrun}({_argshexrun}):
        {_argshexrun} = {_argshexrun}-0xFF78FF
        if {_argshexrun} <= 0x7F:
                    return {_str}({_bytes}([{_argshexrun}]),"utf8")
        elif {_argshexrun} <= 0x7FF:
                    if 1<2:
                            b1 = 0xC0 | ({_argshexrun} >> 6)
                    b2 = 0x80 | ({_argshexrun} & 0x3F)
                    return {_str}({_bytes}([b1, b2]),"utf8")
        elif {_argshexrun} <= 0xFFFF:
                b1 = 0xE0 | ({_argshexrun} >> 12)
                if 2>1:
                    b2 = 0x80 | (({_argshexrun} >> 6) & 0x3F)
                b3 = 0x80 | ({_argshexrun} & 0x3F)
                return {_str}({_bytes}([b1, b2, b3]),"utf8")
        else:
            b1 = 0xF0 | ({_argshexrun} >> 18)
            if 2==2:
                b2 = 0x80 | (({_argshexrun} >> 12) & 0x3F)
            if 1<2<3:
                b3 = 0x80 | (({_argshexrun} >> 6) & 0x3F)
            b4 = 0x80 | ({_argshexrun} & 0x3F)
            return {_str}({_bytes}([b1, b2, b3, b4]),"utf8")
    def _hex(j):
        {_argshexrun} = ''
        for _hex in j:
            {_argshexrun} += ({_hexrun}(_hex))
        return {_argshexrun}
else:"obfuscated"
"""

antipycdc = ''
for i in range(20000): 
    antipycdc += f"你器(你器(你器(你器(你器(你器('test')))))),"
antipycdc = "try:truongquangthangakahoanggiakiet=[" + antipycdc + "]\nexcept:pass"

ANTI_PYCDC = f"""
def 你器(你):
    return 你
try:pass
except:pass
finally:pass
{antipycdc}
finally:int(2008-2006)
"""

def ultra_encrypt_code(code):
    xor_keys = [random.randint(1, 255) for _ in range(4)]
    code = bytes([b ^ xor_keys[i % 4] for i, b in enumerate(code.encode())])
    
    code = base64.b85encode(code)
    code = bz2.compress(code, compresslevel=9) 
    code = zlib.compress(code, level=9) 
    code = marshal.dumps(code)
    code = base64.b85encode(code)
    
    code = bytes([((b << 4) | (b >> 4)) & 0xFF for b in code])
    
    code = base64.b85encode(code)
    code = marshal.dumps(code)
    code = bz2.compress(code, compresslevel=9)
    code = zlib.compress(code, level=9)
    code = base64.b85encode(code)
    
    xor_keys2 = [random.randint(1, 255) for _ in range(3)]
    code = bytes([b ^ xor_keys2[i % 3] for i, b in enumerate(code)])
    
    code = base64.b85encode(code)
    code = zlib.compress(code, level=9)
    code = marshal.dumps(code)
    code = bz2.compress(code, compresslevel=9)
    code = base64.b85encode(code)
    
    code = bytes([((b << 1) | (b >> 7)) & 0xFF for b in code])
    
    code = base64.b85encode(code)
    code = bz2.compress(code, compresslevel=9)
    code = marshal.dumps(code)
    code = zlib.compress(code, level=9)
    code = base64.b85encode(code)
    
    final_xor = random.randint(1, 255)
    code = bytes([b ^ final_xor for b in code])
    
    code = base64.b85encode(code)
    
    return code

def generate_ultra_complex_decoder():
    decoder = f"""
import base64, zlib, bz2, marshal, random, hashlib, itertools

def _malware_decode_layer1(data):
    xor_key1 = 0x7A
    data = bytes([b ^ xor_key1 for b in data])
    data = base64.b85decode(data)
    data = bz2.decompress(data)
    data = zlib.decompress(data)
    data = marshal.loads(data)
    data = base64.b85decode(data)
    return data

def _malware_decode_layer2(data):
    data = bytes([((b >> 3) | (b << 5)) & 0xFF for b in data])
    data = base64.b85decode(data)
    data = zlib.decompress(data)
    data = bz2.decompress(data)
    data = marshal.loads(data)
    data = base64.b85decode(data)
    return data

def _malware_decode_layer3(data):
    xor_key2 = 0x3F
    data = bytes([b ^ xor_key2 for b in data])
    data = base64.b85decode(data)
    data = marshal.loads(data)
    data = bz2.decompress(data)
    data = zlib.decompress(data)
    data = base64.b85decode(data)
    return data

def _malware_decode_layer4(data):
    data = bytes([((b >> 2) | (b << 6)) & 0xFF for b in data])
    data = base64.b85decode(data)
    data = zlib.decompress(data)
    data = marshal.loads(data)
    data = bz2.decompress(data)
    data = base64.b85decode(data)
    return data

def _malware_decode_layer5(data):
    xor_key3 = 0x9C
    data = bytes([b ^ xor_key3 for b in data])
    data = base64.b85decode(data)
    data = bz2.compress(data)
    data = marshal.loads(data)
    data = zlib.compress(data)
    data = base64.b85decode(data)
    return data

def decode_ultra_malware_payload(encoded_data):
    try:
        data = _ultra_decode_layer1(encoded_data)
        data = _ultra_decode_layer2(data)
        data = _ultra_decode_layer3(data)
        data = _ultra_decode_layer4(data)
        data = _ultra_decode_layer5(data)
        
        return marshal.loads(data)
    except Exception as e:
        raise Exception(f"Ultra malware decode failed: {{e}}")

"""
    
    for i in range(250):  
        func_name = rd()
        decoder += f"""
def {func_name}_ultra():
    return {random.randint(1, 999999)}
"""
    
    return decoder
def _moreobf(tree):
    import random

    def rd():
        return str(random.randint(0x1E000000000, 0x7E000000000))

    def junk(en, max_value):
        cases = []
        line = max_value + 1
        for i in range(random.randint(2, 5)):  
            case_name = "__"+rd()
            case_body = [
                ast.If(
                    test=ast.Compare(
                        left=ast.Subscript(
                            value=ast.Attribute(
                                value=ast.Name(id=en), 
                                attr='args'
                            ), 
                            slice=ast.Constant(value=0)
                        ), 
                        ops=[ast.Eq()], 
                        comparators=[ast.Constant(value=line)]
                    ), 
                    body=[
                        ast.Assign(
                            targets=[ast.Name(id=case_name)], 
                            value=ast.Constant(value=random.randint(0xFFFFF, 0xFFFFFFFFFFFF)), 
                            lineno=None
                        )
                    ], 
                    orelse=[]
                )
            ]
            cases.extend(case_body)
            line += 1
        return cases

    def bl(body):
        var = "__"+rd()
        en = "__"+rd()

        tb = [
            ast.AugAssign(
                target=ast.Name(id=var), 
                op=ast.Add(), 
                value=ast.Constant(value=1)
            ),
            ast.Try(
                body=[
                    ast.Raise(
                        exc=ast.Call(func=ast.Name(id='MemoryError'), 
                                     args=[ast.Name(id=var)], 
                                     keywords=[])
                    )
                ],
                handlers=[
                    ast.ExceptHandler(
                        type=ast.Name(id='MemoryError'), 
                        name=en, 
                        body=[]
                    )
                ],
                orelse=[],
                finalbody=[]
            )
        ]
        
        for i in body:
            tb[1].handlers[0].body.append(
                ast.If(
                    test=ast.Compare(
                        left=ast.Subscript(
                            value=ast.Attribute(
                                value=ast.Name(id=en), 
                                attr='args'
                            ), 
                            slice=ast.Constant(value=0)
                        ), 
                        ops=[ast.Eq()], 
                        comparators=[ast.Constant(value=1)]
                    ), 
                    body=[i], 
                    orelse=[]
                )
            )
        
        tb[1].handlers[0].body.extend(junk(en, len(body) + 1))
        
        node = ast.Assign(
            targets=[ast.Name(id=var)], 
            value=ast.Constant(value=0), 
            lineno=None
        )
        
        return [node] + tb

    def _bl(node):
        olb = node.body

        var = "__"+rd()
        en = "__"+rd()

        tb = [
            ast.AugAssign(
                target=ast.Name(id=var), 
                op=ast.Add(), 
                value=ast.Constant(value=1)
            ),
            ast.Try(
                body=[
                    ast.Raise(
                        exc=ast.Call(func=ast.Name(id='MemoryError'), 
                                     args=[ast.Name(id=var)], 
                                     keywords=[])
                    )
                ],
                handlers=[
                    ast.ExceptHandler(
                        type=ast.Name(id='MemoryError'), 
                        name=en, 
                        body=[]
                    )
                ],
                orelse=[],
                finalbody=[]
            )
        ]
        for i in olb:
            tb[1].handlers[0].body.append(
                ast.If(
                    test=ast.Compare(
                        left=ast.Subscript(
                            value=ast.Attribute(
                                value=ast.Name(id=en), 
                                attr='args'
                            ), 
                            slice=ast.Constant(value=0)
                        ), 
                        ops=[ast.Eq()], 
                        comparators=[ast.Constant(value=1)]
                    ), 
                    body=[i], 
                    orelse=[]
                )
            )
        tb[1].handlers[0].body.extend(junk(en, len(olb) + 1))
        node.body = [
            ast.Assign(
                targets=[ast.Name(id=var)], 
                value=ast.Constant(value=0), 
                lineno=None
            )
        ] + tb
        return node
    
    def on(node):
        if isinstance(node, ast.FunctionDef):
            return _bl(node)
        return node
    
    nb = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            nb.append(on(node))
        elif isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            nb.extend(bl([node]))
        elif isinstance(node, ast.Expr):
            nb.extend(bl([node]))
        else:
            nb.append(node)
    tree.body = nb
    return tree

def __moreobf(x):
    return ast.unparse(_moreobf(ast.parse(x)))

def fm(node: ast.JoinedStr) -> ast.Call:
    return ast.Call(
        func=ast.Attribute(
            value=ast.Constant(value="{}" * len(node.values)),
            attr="format",
            ctx=ast.Load(),
        ),
        args=[
            value.value if isinstance(value, ast.FormattedValue) else value
            for value in node.values
        ],
        keywords=[],
    )

def _syntax(x):
    def v(node):
        if node.name:
            for statement in node.body:
                ten = ast.Try(
                    body=[ast.parse(f"{_eval}('0/0')"),ast.parse(f"""if "ngocuyen" == "deptrai":{rd()},{rd()},{rd()},{rd()}\nelse:pass""")],
                    handlers=[
                        ast.ExceptHandler(
                            type=ast.Name(id='ZeroDivisionError', ctx=ast.Load()),
                            name=None,
                            body=[z(statement)]
                        )
                    ],
                    orelse=[],
                    finalbody=[]
                )
                node.body[node.body.index(statement)] = ten
            return node
    def z(statement):
        return ast.Try(
            body=[ast.parse(f"{_eval}('0/0')")],
            handlers=[
                ast.ExceptHandler(
                    type=ast.Name(id='ZeroDivisionError', ctx=ast.Load()),
                    name=None,
                    body=[statement]
                )
            ],
            orelse=[ast.Pass()],
            finalbody=[ast.parse("str(100)")]
        )
    tree = ast.parse(x)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            v(node)
    st = ast.unparse(tree)
    return st

def obfuscate(node):
    for i in ast.walk(node):
        if isinstance(i, ast.Global):
            continue
        if isinstance(i, ast.Nonlocal):
            continue
        for f, v in ast.iter_fields(i):
            if isinstance(v, list):
                ar = []
                for j in v:
                    try:
                        if isinstance(j, ast.Constant) and isinstance(j.value, str):
                            ar.append(ast.parse(obfstr(j.value)).body[0].value)
                        elif isinstance(j, ast.Constant) and isinstance(j.value, int):
                            ar.append(ast.parse(obfint(j.value)).body[0].value)
                        elif isinstance(j, ast.JoinedStr):
                            ar.append(fm(j))
                        elif isinstance(j, ast.AST):
                            ar.append(j)
                    except Exception as e:
                        print(f"Error processing node {j}: {e}")
                        ar.append(j)
                setattr(i, f, ar)
            else:
                try:
                    if isinstance(v, ast.Constant) and isinstance(v.value, str):
                        setattr(i, f, ast.parse(obfstr(v.value)).body[0].value)
                    elif isinstance(v, ast.Constant) and isinstance(v.value, int):
                        setattr(i, f, ast.parse(obfint(v.value)).body[0].value)
                    elif isinstance(v, ast.JoinedStr):
                        setattr(i, f, fm(v))
                except Exception as e:
                    print(f"Error processing field {f} with value {v}: {e}")

def rename_function(node, ol, nn):
    for i in ast.walk(node):
        if isinstance(i, ast.FunctionDef) and i.name == ol:
            i.name = nn
        elif isinstance(i, ast.Attribute) and isinstance(i.value, ast.Name) and i.value.id == ol:
            i.value.id = nn
        elif isinstance(i, ast.Call) and isinstance(i.func, ast.Name) and i.func.id == ol:
            i.func.id = nn
        elif isinstance(i, ast.Name) and i.id == ol:
            i.id = nn
    return node

def random_match_case():
    var1 = ast.Constant(value=randomint(), kind=None)
    var2 = ast.Constant(value=randomint(), kind=None)
    return ast.Match(
        subject=ast.Compare(
            left=var1,
            ops=[ast.Eq()],
            comparators=[var2],
        ),
        cases=[
            ast.match_case(
                pattern=ast.MatchValue(value=ast.Constant(value=True, kind=None)),
                body=[
                    ast.Assign(
                        lineno=0,
                        col_offset=0,
                        targets=[],
                        value=[ast.Raise(
                    exc=ast.Call(
                        func=ast.Name(id="MemoryError", ctx=ast.Load()),
                        args=[],
                        keywords=[ast.Constant(value=True, kind=None)],
                    ),)],
                    )
                ],
            ),
            ast.match_case(
                pattern=ast.MatchValue(value=ast.Constant(value=False, kind=None)),
                body=[
                    ast.Assign(
                        lineno=0,
                        col_offset=0,
                        targets=[ast.Name(id=rd(), ctx=ast.Store())],
                        value=ast.Constant(value=[[True], [False]], kind=None),
                    ),
                    ast.Expr(
                        lineno=0,
                        col_offset=0,
                        value=ast.Call(
                            func=ast.Name(id=_str, ctx=ast.Load()),
                            args=[ast.Constant(value=[rd()], kind=None)],
                            keywords=[],
                        ),
                    ),
                ],
            ),
        ],
    )

def trycatch(body, loop):
    ar = []
    for x in body:
        j = x
        for _ in range(2):  
            j = ast.Try(
                body=[random_match_case()],
                handlers=[
                    ast.ExceptHandler(
                        type=ast.Name(id="MemoryError", ctx=ast.Load()),
                        name=rd(),
                        body=[j],
                    )
                ],
                orelse=[],
                finalbody=[],
            )
            j.body.append(
                ast.Raise(
                    exc=ast.Call(
                        func=ast.Name(id="MemoryError", ctx=ast.Load()),
                        args=[],
                        keywords=[ast.Constant(value=True, kind=None)],
                    ),
                    cause=None,
                )
            )
        ar.append(j)
    return ar

def obf(code):
    def ps(x):
        return ast.parse(x)
    code = rename_function(ps(code),"print",__print)
    code = rename_function(ps(code),"input",__input)
    tree = ps(code)
    obfuscate(tree)
    tbd = trycatch(tree.body, 1)
    def ast_to_code(node):
        return ast.unparse(node)
    j = ast_to_code(tbd)
    return j

dark = Col.dark_gray
light = Col.light_gray
purple = Col.purple
bpurple = Col.pink
cyan = Col.cyan
red = Col.red
green = Col.green
blue = Col.blue
yellow = Col.yellow

banner = f"""
                    /,                                  **                      
                 #@@@@@@@#                          @@@@@@@@,                   
                @@@@@@@@@@@@.                    *@@@@@@@@@@@/                  
               *@@@@@@@@@@@@@@/                &@@@@@@@@@@@@@@                  
               @@@@@@@@@@@@@@@@@(            &@@@@@@@@@@@@@@@@&                 
              /@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                 
              @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#                
              @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                
             .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                
             (@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@(              
           .@@@@@@@@@/      .&@@@@@@@@@@@@@@@@@@@@@.        (@@@@@@/            
          @@@@@@@@.             @@@@@@@@@@@@@@@@,              @@@@@@           
        .@@@@@@@%                 @@@@@@@@@@@@@                 ,@@@@@          
       *@@@@@@@%                   @@@@@@@@@@@              ,,   (@@@@@         
       @@@@@@@@            @. &@(  %@@@@@@@@@(           &@   @@( @@@@@(        
      @@@@@@@@@          /@/   @@@ (@@@@@@@@@(          &@@  /@@@%@@@@@@        
      @@@@@@@@@          @@@@@@@@@@@@@@@@@@@@@          @@@@@@@@@@@@@@@@*/*,.   
      @@@@@@@@@@        .@@@@@@@@@@@@@@@@@@@@@%         @@@@@@@@@@@@@@@*        
 ,(%@@@@@@@@@@@@@        @@@@@@@@@@@@@@@@@@@@@@@        #@@@@@@@@@@@@@%         
      %@@@@@@@@@@@@.      @@@@@@@@@@@@@@@@@@@@@@@@,      ,@@@@@@@@@@@@@                  
       &@@@@@@@@@@@@@@@%(/#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&    #@,     
        ,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#         @&   
      /@* .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&              #@ 
    @@       .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&     ,&@%.           
  .#              *@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*         @@@@@@@@         
                           ,@@@@@@@@@@@@@@@@@@@@@@@@@#         #@@@@@@@@*       
                           @@@@@@@@@@@@@@@@@@@@@@@@@@@@          @@@@@@@@       
                          @@@@@@@@@@@@@@@@@@@@@@@@@@@@@          @@@@@@@       
                          *@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%        #@@@@@@%       
                           @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@(..(@@@@@@@@@*        
                            @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@(           
                              @@@@@@@@@@@@@@@@@@@@@@@@,         
"""

print(Colorate.Vertical(Colors.cyan_to_green, banner))

text = f"""
[>] Running with Python {sys.version.split()[0]}
[>] ULTRA OBFUSCATOR v5.0 - Advanced Code Protection & Encryption
[>] Developer: Hoang Gia Kiet
[>] Links: https://github.com/giakietdev/obfuscater/
[>] Features: Multi-layer Encryption, Anti-Debug, Anti-Decompiler, Maximum Compression
[>] Modes: [1] LOW [2] MEDIUM [3] HIGH [4] ULTRA
"""

print(Colorate.Vertical(Colors.cyan_to_green, text))

def stage(text: str, symbol: str = '[>]', col1 = cyan, col2 = None) -> str:
    if col2 is None:
        col2 = cyan if symbol == '[>]' else green
    return f"""{Colorate.Color(cyan, symbol)} {Colorate.Vertical(Colors.cyan_to_green, text)}"""

v = input
_v = print
def input(x):
    return v(stage(x))
def print(x,*k):
    return _v(stage(x),*k)

_file = input(" Enter the python file you wish to obfuscate [script.py]: ")

while True:
    try:
        with open(_file, "r", encoding="utf8") as file:
            code = file.read()
        break
    except FileNotFoundError:
        _file = input(" Enter the python file you wish to obfuscate [script.py]: ")

while True:
    try:
        mode = int(input(" Select mode (1-4): "))
        if 1 <= mode <= 4:
            break
    except ValueError:
        pass

moreobf = input(" Extra obfuscation [y/n]: ")
antidebug = input(" Anti-debug protection [y/n]: ")
method = input(" Compilation mode [y/n]: ")

check = 0
code = _syntax(code)

if moreobf.upper() == "Y":
    code = __moreobf(code)
    check = 5

checkver = f"""
import sys
if '{sys.version[0]+sys.version[1]+sys.version[2]+sys.version[3]}' not in sys.version:
    input("Your python version does not work on this code, please install {sys.version[0]+sys.version[1]+sys.version[2]+sys.version[3]}")
    __import__("sys").exit()
"""
author = f"""
__author__ = "hoanggiakiet"
__fullname__ = "Hoàng Gia Kiệt", "Trương Quang Thắng"
__discord__ ="discord.gg/thick1minh"
__version__ = "5.0"
__description__ = "OBFUSCATOR v5.0"
__minimumpythonversion__ = "3.10"
__url__ = "https://github.com/giakietdev/obfuscater/"
{checkver}
"""

anti = r"""
import traceback, marshal, sys, os, time

ch = set()
am = {'builtins', '__main__'}

def vv():
    raise MemoryError('>> GOOD LUCK!! CONMEMAY') from None

def cb(fn):
    if callable(fn) and fn.__module__ not in am:
        ch.add(fn.__module__)
        vv()

def ba(fn):
    def hi(*args, **kwargs):
        if args and args[0] in ch:
            vv()
        return fn(*args, **kwargs)
    return hi

def bh():
    stack = traceback.extract_stack()
    for frame in stack[:-2]:
        if frame.filename != __file__:
            vv()

def ck(fn, md):
    if callable(fn) and fn.__module__ != md:
        ch.add(md)
        raise ImportError(f'>> Detect [{fn.__name__}] call [{md}] ! <<') from None

def ic(md, nf):
    module = __import__(md)
    funcs = nf if isinstance(nf, list) else [nf]
    [ck(getattr(module, func, None), md) for func in funcs]

def lf(val, xy):
    return callable(val) and xy and val.__module__ != xy.__name__

def kt(lo):
    if any(lf(val, xy) for val, xy in lo):
        vv()

def ct(md, nf):
    module = __import__(md)
    func = getattr(module, nf, None)
    if func is None:
        vv()
    tg = type(func)
    def cf(func):
        if type(func) != tg:
            vv()
    cf(func)
    return func

def ic_type(md, nf):
    func = ct(md, nf)
    ck(func, md)

def nc():
    __import__('sys').settrace(lambda *args, **keys: None)
    __import__('sys').modules['marshal'] = None
    __import__('sys').modules['marshal'] = type(__import__('sys'))('marshal')
    __import__('sys').modules['marshal'].loads = marshal.loads

def sc():
    nk = {
        'marshal': 'loads'
    }
    [ic_type(md, nf) for md, nf in nk.items()]

    lo = [
        (__import__('marshal').loads, marshal)
    ]
    kt(lo)
    nc()
def check_debugger():
    try:
        if hasattr(sys, 'gettrace') and sys.gettrace():
            vv()
    except:
        pass

def check_timing():
    start = time.time()
    time.sleep(0.001)
    if time.time() - start > 0.1:
        vv()

sc()
bh()
check_debugger()
check_timing()
"""

if antidebug.upper() == "Y":
    code = anti+code

for i in range(mode):
    code = obf(code)

if method.upper() != "Y":
    code = var + code
    if check == 5:
        try:
            code = __moreobf(code)
        except Exception as e:
            print(f"Warning: More obfuscation failed: {e}")
            pass
else:
    if check == 5:
        try:
            code = __moreobf(code)
        except Exception as e:
            print(f"Warning: More obfuscation failed: {e}")
            pass
    
    try:
        malware_payload = generate_malware_payload()
        code = malware_payload + "\n" + ANTI_PYCDC + code
        
        compiled_code = marshal.dumps(compile(code, "", "exec"))
        
        encrypted_code = ultra_encrypt_code(compiled_code)
        
        l = len(encrypted_code)
        part1 = encrypted_code[: l // 10]
        part2 = encrypted_code[l // 10: l // 5]
        part3 = encrypted_code[l // 5: 3 * l // 10]
        part4 = encrypted_code[3 * l // 10: 2 * l // 5]
        part5 = encrypted_code[2 * l // 5: l // 2]
        part6 = encrypted_code[l // 2: 3 * l // 5]
        part7 = encrypted_code[3 * l // 5: 7 * l // 10]
        part8 = encrypted_code[7 * l // 10: 4 * l // 5]
        part9 = encrypted_code[4 * l // 5: 9 * l // 10]
        part10 = encrypted_code[9 * l // 10:]
        
        _f = "for"
        _i = "in"
        _t = rd()
        _t2 = rd()
        _t3 = rd()
        _t4 = rd()
        _t5 = rd()
        
        decoder = generate_ultra_complex_decoder()
        
        code = author + decoder + var + f"""

def ultra_malware_bytecode():
    ultra_exec = globals().update
    if True:
        ultra_exec({ngoac}**{ngoac} _hex({_uni("en")}): {_temp} {_f} {_temp1}, {_temp} {_i} {_vars}({___import__}(_hex({_uni("marshal")}))).items() if {_movdiv}({_temp}) and {_temp1} == _hex({_uni("loads")}){_ngoac}, **{ngoac}{_temp1}: {_temp} {_f} {_temp1}, {_temp} {_i} {_vars}({___import__}(_hex({_uni("marshal")}))).items() if {_movdiv}({_temp}) and {_temp1} != _hex({_uni("loads")}){_ngoac}{_ngoac})
    else:"ultra_exec"
    if 1>2:
        {obfint(3)}
    else:
        ultra_exec({ngoac}**{ngoac}_hex({_uni("giakiethoang")}): {_temp} {_f} {_temp1}, {_temp} {_i} {_vars}({___import__}(_hex({_uni("zlib")}))).items() if {_movdiv}({_temp}) and {_temp1} == _hex({_uni("decompress")}){_ngoac}, **{ngoac}{_temp1}: {_temp} {_f} {_temp1}, {_temp} {_i} {_vars}({___import__}(_hex({_uni("zlib")}))).items() if {_movdiv}({_temp}) and {_temp1} != _hex({_uni("decompress")}){_ngoac}{_ngoac})
    ultra_exec({ngoac}**{ngoac}_hex({_uni("kietdev")}): {_temp} {_f} {_temp1}, {_temp} {_i} {_vars}({___import__}(_hex({_uni("bz2")}))).items() if {_movdiv}({_temp}) and {_temp1} == _hex({_uni("decompress")}){_ngoac}, **{ngoac}{_temp1}: {_temp} {_f} {_temp1}, {_temp} {_i} {_vars}({___import__}(_hex({_uni("bz2")}))).items() if {_movdiv}({_temp}) and {_temp1} != _hex({_uni("decompress")}){_ngoac}{_ngoac})
    ultra_exec()
    ultra_exec({ngoac}**{ngoac}_hex({_uni("obf")}): {_t} {_f} {_temp1}, {_t} {_i} {_vars}({___import__}(_hex({_uni("base64")}))).items() if {_movdiv}({_t}) and {_temp1} == _hex({_uni("b85decode")}){_ngoac}, **{ngoac}{_temp1}: {_t} {_f} {_temp1}, {_t} {_i} {_vars}({___import__}(_hex({_uni("base64")}))).items() if {_movdiv}({_t}) and {_temp1} != _hex({_uni("b85decode")}){_ngoac}{_ngoac})
    ultra_exec()
    ultra_exec({ngoac}**{ngoac}_hex({_uni("ultra")}): {_t} {_f} {_temp1}, {_t} {_i} {_vars}({___import__}(_hex({_uni("builtins")}))).items() if {_movdiv}({_t}) and {_temp1} == _hex({_uni("exec")}){_ngoac}, **{ngoac}{_temp1}: {_t} {_f} {_temp1}, {_t} {_i} {_vars}({___import__}(_hex({_uni("builtins")}))).items() if {_movdiv}({_t}) and {_temp1} != _hex({_uni("eval")}){_ngoac}{_ngoac})
    ultra_exec()
    ultra_exec({ngoac}**{ngoac}_hex({_uni("compressed")}): {_t2} {_f} {_temp1}, {_t2} {_i} {_vars}({___import__}(_hex({_uni("random")}))).items() if {_movdiv}({_t2}) and {_temp1} == _hex({_uni("randint")}){_ngoac}, **{ngoac}{_temp1}: {_t2} {_f} {_temp1}, {_t2} {_i} {_vars}({___import__}(_hex({_uni("random")}))).items() if {_movdiv}({_t2}) and {_temp1} != _hex({_uni("randint")}){_ngoac}{_ngoac})
    ultra_exec()
    ultra_exec({ngoac}**{ngoac}_hex({_uni("malware")}): {_t3} {_f} {_temp1}, {_t3} {_i} {_vars}({___import__}(_hex({_uni("hashlib")}))).items() if {_movdiv}({_t3}) and {_temp1} == _hex({_uni("md5")}){_ngoac}, **{ngoac}{_temp1}: {_t3} {_f} {_temp1}, {_t3} {_i} {_vars}({___import__}(_hex({_uni("hashlib")}))).items() if {_movdiv}({_t3}) and {_temp1} != _hex({_uni("md5")}){_ngoac}{_ngoac})
    ultra_exec()
    ultra_exec({ngoac}**{ngoac}_hex({_uni("payload")}): {_t4} {_f} {_temp1}, {_t4} {_i} {_vars}({___import__}(_hex({_uni("itertools")}))).items() if {_movdiv}({_t4}) and {_temp1} == _hex({_uni("chain")}){_ngoac}, **{ngoac}{_temp1}: {_t4} {_f} {_temp1}, {_t4} {_i} {_vars}({___import__}(_hex({_uni("itertools")}))).items() if {_movdiv}({_t4}) and {_temp1} != _hex({_uni("chain")}){_ngoac}{_ngoac})
    ultra_exec()
    ultra_exec({ngoac}**{ngoac}_hex({_uni("complex")}): {_t5} {_f} {_temp1}, {_t5} {_i} {_vars}({___import__}(_hex({_uni("base64")}))).items() if {_movdiv}({_t5}) and {_temp1} == _hex({_uni("b85encode")}){_ngoac}, **{ngoac}{_temp1}: {_t5} {_f} {_temp1}, {_t5} {_i} {_vars}({___import__}(_hex({_uni("base64")}))).items() if {_movdiv}({_t5}) and {_temp1} != _hex({_uni("b85encode")}){_ngoac}{_ngoac})
ultra_malware_bytecode()

_en  {'  '* 999}={part1}
_giakiethoang  {'  '* 999}={part2}
_obfuscatedchallenge  {'  '* 999}={part3}
_obf  {'  '* 999}={part4}
_ultra  {'  '* 999}={part5}
_compressed  {'  '* 999}={part6}
_malware  {'  '* 999}={part7}
_payload  {'  '* 999}={part8}
_complex  {'  '* 999}={part9}
_bytecode  {'  '* 999}={part10}

try:
    combined_data = _en + _giakiethoang + _obfuscatedchallenge + _obf + _ultra + _compressed + _malware + _payload + _complex + _bytecode
    
    decoded_data = decode_ultra_malware_payload(combined_data)
    
    exec(decoded_data)
    
except Exception as e:
    print(f"Ultra compressed malware execution failed: {{e}}")
    try:
        exec(
        en(
        giakiethoang(
        kietdev(
        obf(
        _en+_giakiethoang+_obfuscatedchallenge+_obf+_ultra+_compressed+_malware+_payload+_complex+_bytecode)))))
    except Exception as e2:
        print(f"Fallback execution also failed: {{e2}}")

"""
    except Exception as e:
        print(f"Error during ultra compressed malware encryption: {e}")
    code = ANTI_PYCDC + code
    code = marshal.dumps(compile(code, "", "exec"))
    code = zlib.compress(code, level=9)
    code = bz2.compress(code, compresslevel=9)  
    code = base64.b85encode(code)
    l = len(code)
    part1 = code[: l // 5]
    part2 = code[l // 5: 2 * l // 5]
    part3 = code[2 * l // 5: 3 * l // 5]
    part4 = code[3 * l // 5: 4 * l // 5]
    part5 = code[4 * l // 5:]
    _f = "for"
    _i = "in"
    _t = rd()
    code = author + var + f"""

def ultra_compressed_bytecode():
    ultra_exec = globals().update
    if True:
        ultra_exec({ngoac}**{ngoac} _hex({_uni("en")}): {_temp} {_f} {_temp1}, {_temp} {_i} {_vars}({___import__}(_hex({_uni("marshal")}))).items() if {_movdiv}({_temp}) and {_temp1} == _hex({_uni("loads")}){_ngoac}, **{ngoac}{_temp1}: {_temp} {_f} {_temp1}, {_temp} {_i} {_vars}({___import__}(_hex({_uni("marshal")}))).items() if {_movdiv}({_temp}) and {_temp1} != _hex({_uni("loads")}){_ngoac}{_ngoac})
    else:"ultra_exec"
    if 1>2:
        {obfint(3)}
    else:
        ultra_exec({ngoac}**{ngoac}_hex({_uni("giakiethoang")}): {_temp} {_f} {_temp1}, {_temp} {_i} {_vars}({___import__}(_hex({_uni("zlib")}))).items() if {_movdiv}({_temp}) and {_temp1} == _hex({_uni("decompress")}){_ngoac}, **{ngoac}{_temp1}: {_temp} {_f} {_temp1}, {_temp} {_i} {_vars}({___import__}(_hex({_uni("zlib")}))).items() if {_movdiv}({_temp}) and {_temp1} != _hex({_uni("decompress")}){_ngoac}{_ngoac})
    ultra_exec({ngoac}**{ngoac}_hex({_uni("kietdev")}): {_temp} {_f} {_temp1}, {_temp} {_i} {_vars}({___import__}(_hex({_uni("bz2")}))).items() if {_movdiv}({_temp}) and {_temp1} == _hex({_uni("decompress")}){_ngoac}, **{ngoac}{_temp1}: {_temp} {_f} {_temp1}, {_temp} {_i} {_vars}({___import__}(_hex({_uni("bz2")}))).items() if {_movdiv}({_temp}) and {_temp1} != _hex({_uni("decompress")}){_ngoac}{_ngoac})
    ultra_exec()
    ultra_exec({ngoac}**{ngoac}_hex({_uni("obf")}): {_t} {_f} {_temp1}, {_t} {_i} {_vars}({___import__}(_hex({_uni("base64")}))).items() if {_movdiv}({_t}) and {_temp1} == _hex({_uni("b85decode")}){_ngoac}, **{ngoac}{_temp1}: {_t} {_f} {_temp1}, {_t} {_i} {_vars}({___import__}(_hex({_uni("base64")}))).items() if {_movdiv}({_t}) and {_temp1} != _hex({_uni("b85decode")}){_ngoac}{_ngoac})
    ultra_exec()
    ultra_exec({ngoac}**{ngoac}_hex({_uni("ultra")}): {_t} {_f} {_temp1}, {_t} {_i} {_vars}({___import__}(_hex({_uni("builtins")}))).items() if {_movdiv}({_t}) and {_temp1} == _hex({_uni("exec")}){_ngoac}, **{ngoac}{_temp1}: {_t} {_f} {_temp1}, {_t} {_i} {_vars}({___import__}(_hex({_uni("builtins")}))).items() if {_movdiv}({_t}) and {_temp1} != _hex({_uni("eval")}){_ngoac}{_ngoac})
ultra_compressed_bytecode()

_nodeobf  {'  '* 999}={part1}
_giakiethoang  {'  '* 999}={part2}
_obfuscatedchallenge  {'  '* 999}={part3}
_obf  {'  '* 999}={part4}
_ultra  {'  '* 999}={part5}
try:
    exec(
    en(
    giakiethoang(
    kietdev(
    obf(
    _nodeobf+_giakiethoang+_obfuscatedchallenge+_obf+_ultra)))))
except Exception as e:
    print(e)

"""

print("[>] " + "=" * 50)

output_file = "obfuscated-" + _file
open(output_file, "w", encoding="utf8").write(str(code))

print(f"[>] Code has been successfully obfuscated @ {output_file}")
try:
    compile(code, "", "exec")
    print("[>] Code compiled successfully!")
except Exception as e:
    print(f"[>] Warning: Output code may have issues: {e}")
    print("[>] The obfuscated code has been saved but may need manual review.")

print("[>] Would you like to compile to an exe [y/n]: ")
