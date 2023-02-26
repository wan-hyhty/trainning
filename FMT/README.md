# Giới thiệu chung
- %p, in địa chỉ trên thanh ghi  
  - đối với biến khi a = "A"; print("%p", a) thì khi đến hàm print() trên thanh ghi rsi là 0x41 nên %p sẽ in ra giá trị 0x41  
  - đối với mảng khi a[10] = "ABCDEABCDE" thì print("%p", a) sẽ in ra địa chỉ đầu của mảng  
- %c in ra 1 byte đang có trên thanh ghi và in ra theo ascii nghĩa là 0x1234 thì %c sẽ in ra 0x34 và đổi về kí tự theo mã ascii  
- %s nhận vào địa chỉ và in ra chuỗi mà địa chỉ đó đang trỏ đến, còn đối với mảng, khi print("%s", a) thì thanh ghi sẽ tự truyền địa chỉ đầu mảng vào và 
- %s sẽ trỏ đến địa chỉ đó và in ra cho đến khi gặp 0x00  
- %n đếm số lượng byte được in ra trước nó, rồi ghi vào biến được truyền địa chỉ

> Lưu ý:  
> Đối với 32bit: in dữ liệu trên stack  
>	64bit: 5% đầu của 5 thanh ghi, % thứ 6 là dữ liệu trên stack  


# leak dữ liệu bằng %p
%p sẽ in dữ liệu trên stack dưới dạng hex()
p64(): pack64 chuyển hex sang bytes
u64():unpack chuyển bytes sang hex

# leak dữ liệu = %s
%s leak dữ liệu địa chỉ mà địa chỉ trỏ đến (con) trong con trỏ  

Lưu ý khi fread() đọc dữ liệu từ file vào chương trình, khi đó ta cần lưu ý ,cẩn thận có thể sẽ chia flag ra nhiều phần. 

# %n
để thay đổi dữ liệu của một biến, ta sẽ cho in ra %{giá trị cần thay đổi}$c sau đó dùng %n để đọc các byte đã in ra và lưu vào địa chỉ mà %n trỏ đến  
Trường hợp giá trị cần thay đổi quá lớn thì có thể chia thành 2 lần in, tuy nhiên lần thứ 2, %n sẽ đọc n byte của lần 1 và cộng m byte của lần 2

Bài này em chưa xong =)))
