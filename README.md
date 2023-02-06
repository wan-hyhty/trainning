Đầu tiên e sử dụng ida thì thấy có dòng if như hình 
![image](https://user-images.githubusercontent.com/111769169/217061789-be75c449-b683-4163-832f-76cd1bb22527.png)
Em kiểm tra trên mạng thì đại loại lệnh strcmp() sẽ so sánh 2 chuỗi đầu vào, nếu giống nhau (bằng nhau) thì lệnh trả về giá trị 0, còn lại sẽ là khác 0
=> Em hiểu nếu em trả lời là no thì sẽ exit luôn

tiếp đến đoạn sau e chú ý
![image](https://user-images.githubusercontent.com/111769169/217062520-7cd23e51-0c1f-49d2-94e2-9c91f34447d5.png)

Em cho chương trình chạy và thấy nó ls ra các file trong shell
![image](https://user-images.githubusercontent.com/111769169/217062915-9da19056-95f0-4e04-bfe4-f8af3918b346.png)

Em tưởng chiếm được shell rồi nên em thử ls hay cat như bình thường thì thấy không tương tác được.

Em chú ý thêm đoạn sau:
![image](https://user-images.githubusercontent.com/111769169/217063283-8ad0ba43-a285-49bb-b45b-f6ad3819f34d.png)
Em hiểu đoạn system nó chỉ ls /bin/ls chứ không như bình thường là /bin/sh để chiếm shell

Đến đây e nghĩ mình sẽ overflow đến biến command và đổi giá trị thành 'hs'
