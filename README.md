Đầu tiên e sử dụng ida thì thấy có dòng if như hình 

![image](https://user-images.githubusercontent.com/111769169/217061789-be75c449-b683-4163-832f-76cd1bb22527.png)

Em kiểm tra trên mạng thì đại loại lệnh strcmp() sẽ so sánh 2 chuỗi đầu vào, nếu giống nhau (bằng nhau) thì lệnh trả về giá trị 0, còn lại sẽ là khác 0
=> Em hiểu nếu em trả lời là no thì sẽ exit luôn

Em cho chương trình chạy và thấy nó ls ra các file trong shell

![image](https://user-images.githubusercontent.com/111769169/217062915-9da19056-95f0-4e04-bfe4-f8af3918b346.png)

Em tưởng chiếm được shell rồi nên em thử ls hay cat như bình thường thì thấy không tương tác được.

Em chú ý thêm đoạn sau:

![image](https://user-images.githubusercontent.com/111769169/217063283-8ad0ba43-a285-49bb-b45b-f6ad3819f34d.png)

Em hiểu đoạn system nó chỉ ls (ls) chứ không như bình thường là /bin/sh để chiếm shell

Đến đây e nghĩ mình sẽ overflow đến biến command và đổi giá trị /bin/sh

Bây giờ em cần tìm offset từ biến buf đến biến command

![image](https://user-images.githubusercontent.com/111769169/217068190-1a0e30fc-237e-458e-8341-fba66609e9c4.png)

Em thấy biến command được lưu trong thanh RAX và sau đó RAX được lưu vào rbp-0x28

![image](https://user-images.githubusercontent.com/111769169/217069506-f9a798d6-5d0f-4307-804f-c0637cd1c303.png)

tiếp đến e tạo chuỗi 24byte, đặt break ngay lệnh system, em thấy thanh RAX hơi lạ chỗ hex cuối thanh

![image](https://user-images.githubusercontent.com/111769169/217072943-9e2929d3-e534-446f-bd2a-0f91b43ecf07.png)

Em kiểm tra offset của thanh RAX là 8, nghĩa là từ byte thứ 9 trở đi e sẽ overflow được biến command.
Cuối cùng, em dùng tool để đổi từ hs/bin/ thành mã hex và chiếm được shell. Script của em:

![image](https://user-images.githubusercontent.com/111769169/217073904-98003453-baab-46a6-8c9e-6eb21325a4e2.png)

Kết quả là em chiếm được shell và cat được file flag
![image](https://user-images.githubusercontent.com/111769169/217074160-4adaa22b-e45f-4739-a98b-52a718b4b2de.png)
