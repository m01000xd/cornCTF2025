# cornCTF2025
Writeup cornCTF2025
## flag_checker
<img width="603" height="654" alt="image" src="https://github.com/user-attachments/assets/ef7d3b3c-38d5-4c70-8389-29b3e4edd714" />
<img width="548" height="652" alt="image" src="https://github.com/user-attachments/assets/4560e2a3-b66e-4135-84bf-41e4a6a3ff03" />

Chương trình bắt nhập 1 flag dài 170 kí tự, sau đó tách thành các khối 16 byte truyền vào các thanh ghi xmm rồi mã hóa lại
<img width="408" height="65" alt="image" src="https://github.com/user-attachments/assets/4261c2be-ffab-451d-b39f-df158d1cfdda" />

Rồi sau đó so sánh với chuỗi buffer qword_7FF7FEF96078

<img width="1473" height="657" alt="image" src="https://github.com/user-attachments/assets/806c249d-875e-46d5-9e7d-ff9ea2e7face" />

Chuỗi qword_7FF7FEF96078 đã được gọi trước bởi hàm sub_7FF7FEF93410, hàm gọi VirtualAlloc để cấp phát bộ nhớ, sau đó tính toán để lưu các giá trị vào buffer, rồi gọi VirtualProtect để sửa vùng nhớ thành chỉ có quyền đọc ghi
Sau khi chuỗi qword_7FF7FEF96078 được tính toán, nó được truyền làm tham số cùng với input nhập vào được mã hóa rồi truyền vào hàm sub_7FF7FEF91000

<img width="905" height="603" alt="image" src="https://github.com/user-attachments/assets/4bafa9b0-9c44-48c4-b308-14999005d129" />

<img width="811" height="450" alt="image" src="https://github.com/user-attachments/assets/523ad72c-255c-43db-af91-12fca056d3c8" />

Hàm này kiểm tra với từng kí tự trong input với các kí tự trong chuỗi qword_7FF7FEF96078 ở index tương ứng, với index được gán cho rbx ở mỗi nhánh so sánh, so sánh chúng với nhau

Ta thấy mỗi nhánh đều có cấu trúc giống nhau

<img width="312" height="77" alt="image" src="https://github.com/user-attachments/assets/e52d577f-e7ab-4de7-b44f-9479156f4399" />
<img width="331" height="217" alt="image" src="https://github.com/user-attachments/assets/be54b394-6437-40c3-8f27-1e55092017d4" />

Nó dựa vào 5 đoạn jmp ở mỗi khối để xác định được kí tự. Tức là, phải thực hiện liên tiếp 5 lệnh nhảy trong mỗi khối thì ta mới xác định được kí tự đó, vì với mỗi lệnh nhảy, các bit cờ trong e_flag sẽ có thể = 0 hoặc 1 tương ứng.

Mà để thực hiện cả 5 lệnh liên tiếp, thì tức là mình phải làm ngược lại với các lệnh nhảy trong 5 lệnh nhảy trên, tức là nêu là jnz trong code thì sẽ phải là jz ngược lại, để nhảy tiếp xuống lệnh nhảy ở dưới, còn nếu vẫn là jnz thì nó sẽ nhảy sang nhánh khác và bỏ qua 4 lệnh còn lại

<img width="1600" height="522" alt="image" src="https://github.com/user-attachments/assets/f433264d-6695-474a-aaf3-0428fe4c01e3" />

Các bit của các cờ trong thanh ghi eflags

Vì chỉ có 5 jmp, nên theo ảnh, các cờ theo thứ tự là: cf 0, pf 1, zf 2, sf 3, of 4

```python3
import lief
from capstone import *
from capstone.x86_const import X86_REG_RBX

FLAG_BIT_MAP = {
    "jo":  1, "jno": 0,        # OF
    "js":  1, "jns": 0,        # SF
    "je":  1, "jne": 0,        # ZF
    "jz":  1, "jnz": 0,        # ZF
    "jp":  1, "jnp": 0,        # PF
    "jpe": 1, "jpo": 0,        # PF
    "jb":  1, "jae": 0,        # CF
    "jc":  1, "jnc": 0,        # CF
    "jnae": 1, "jnb": 0        # CF
}
BIT_INDEX_MAP = {
    "jo": 4, "jno": 4,
    "js": 3, "jns": 3,
    "je": 2, "jne": 2,
    "jz": 2, "jnz": 2,
    "jp": 1, "jnp": 1,
    "jpe": 1, "jpo": 1,
    "jb": 0, "jae": 0,
    "jc": 0, "jnc": 0,
    "jnae": 0, "jnb": 0,
}
VALID_JCC = set(FLAG_BIT_MAP.keys())

# Load binary
binary = lief.parse("D:/Cybersec/CTF/cornCTF-2025/flags-checker.exe")
text_section = next((s for s in binary.sections if s.name == ".text"), None)
assert text_section, "Không tìm thấy .text"

code = bytes(text_section.content)
base_addr = binary.optional_header.imagebase + text_section.virtual_address

# Init Capstone
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

flag = ["?"] * 170
collecting = False
bits_dict = {}
skip_first = True
rbx_val = None  # Đảm bảo luôn có giá trị

end_bytes = bytes.fromhex("31C04881FF1D3800000F94C05B5FC3")
end_offset = code.find(end_bytes)
if end_offset == -1:
    raise ValueError("Không tìm thấy đoạn kết thúc trong .text")

code = code[:end_offset]
for instr in md.disasm(code, base_addr):
    mnem = instr.mnemonic
    opstr = instr.op_str
    if mnem == "mov" and len(instr.operands) == 2:
        if instr.operands[0].type == CS_OP_REG and instr.operands[0].reg == X86_REG_RBX:
            if instr.operands[1].type == CS_OP_IMM:
                if skip_first:
                    skip_first = False
                    continue
                rbx_val = instr.operands[1].imm
                continue
    if mnem == "add" and opstr == "rdi, rbx":
        collecting = True
        bit = 0
        count = 0
        continue
    if collecting:
        # Nếu là lệnh nhảy hợp lệ
        if mnem in VALID_JCC:
            bit_val = FLAG_BIT_MAP[mnem]
            bit_idx = BIT_INDEX_MAP[mnem]
            bit |= (bit_val ^ 1) << bit_idx
            count += 1

            if count == 5:
                flag[rbx_val] = chr(bit+95)
print(''.join(flag))

    

```







