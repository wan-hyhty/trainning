# Integer Overflow
Có 2 dạng lưu trữ , một là có dấu, hai là không dấu (unsigned) được lưu trữ như sau:  
Khi một kiểu dữ liệu được lưu trữ dưới dạng có dấu (dương và âm) thì trong máy tính dưới mã nhị phân, bit bên trái cùng sẽ quy định dấu, với 0 là dương và 1 là âm  
VD: 0b10001001 (do là kiểu có dấu nên bit trái cùng sẽ biểu diễn dấu, ở vị trí thứ 8 từ phải sang = 2 mũ 8 = -128 + 1 + 8)  
Còn đối với kiểu unsigned, bit trái cùng không còn tác dụng biểu diễn dấu nữa,  
VD: 0b10001001 (vì là kiểu unsigned nên bit 1 trái cùng sẽ biểu diễn là số 128 + 8 + 1)

##### Lưu ý, để nhận biết dữ liệu đầu vào là số dương nếu giá trị hex bé hơn hoặc bằng 0x7f và số âm nếu 0x80  
