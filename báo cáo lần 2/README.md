# Linux Privilege Escalation

## Một số bước cần thực hiện

- Để có thể vừa học lí thuyết vừa có thể thực hành ta cần chuẩn bị một số thứ sau
  - Đầu tiên cần có 2 ubuntu, bản 20.04 và 20.05 hoặc các bản tương ứng ([20.05](https://www.microsoft.com/store/productId/9MTTCL66CPXJ) [20.04](https://www.microsoft.com/store/productId/9PN20MSR04DW))
  - Ở đây em chọn bản 20.05 là bản tạo server

### setup server

- Đầu tiên, ở bản 20.05 ta sẽ chạy câu lện sau

`sudo apt-get install openssh-server`  
![image](https://user-images.githubusercontent.com/111769169/226509561-dc21236a-ead2-49ea-a8af-1b6a8a80420d.png)

- tiếp đên câu lệnh `sudo service ssh status`

![image](https://user-images.githubusercontent.com/111769169/226509656-db7afd86-681e-4dbe-972f-c197defe34d4.png)

- Nếu nó đã `* sshd is running` thì ta sẽ `ssh localhost`
- tiếp đến ta chạy câu lệnh `sudo nano /etc/ssh/sshd_config`, ta sửa lại như hình

![image](https://user-images.githubusercontent.com/111769169/226510123-1b143bee-bdf3-4262-8eec-aef8096fc33c.png)

![image](https://user-images.githubusercontent.com/111769169/226510582-7c24f117-ba01-4697-889a-463bbfc5479c.png)

- Việc setup khá là khó khăn nên có thể liên lạc em để em tạo server

---

## Khái niệm một số lỗ hổng

### Misconfigured File Permission

- Theo chat-gpt:

```
"Misconfigured File Permission" là một lỗi bảo mật phổ biến trên các hệ thống Unix/Linux. Nó xảy ra khi quyền truy cập vào các tệp tin và thư mục không được cấu hình chính xác. Điều này có thể cho phép kẻ tấn công truy cập và sửa đổi các tệp tin và thư mục mà họ không được phép truy cập thông thường.

Ví dụ, nếu một tệp tin được cấu hình với quyền đọc và ghi cho người dùng không được phép truy cập thông thường, kẻ tấn công có thể truy cập trực tiếp vào tệp tin bằng cách sử dụng lệnh cat, less, more,... để đọc nội dung của tệp tin hoặc sử dụng lệnh echo để ghi dữ liệu vào tệp tin.

"Misconfigured File Permission" có thể xảy ra do nhiều nguyên nhân khác nhau, bao gồm cấu hình sai trong quá trình cài đặt hệ thống, sử dụng các tệp tin và thư mục mặc định của hệ thống mà không cấu hình chính xác quyền truy cập hoặc sử dụng các công cụ quản lý tệp tin và thư mục bị lỗi. Để ngăn chặn lỗi bảo mật này, người quản trị hệ thống cần phải kiểm tra và cấu hình chính xác quyền truy cập cho các tệp tin và thư mục trên hệ thống.
```

- Có các kĩ thuật khai thác lỗ hổng `Misconfigured File Permission` như:

  - Truy cập các tệp tin và thư mục bị cấu hình sai quyền truy cập: Kẻ tấn công có thể sử dụng các lệnh Unix/Linux để truy cập các tệp tin và thư mục mà họ không được phép truy cập thông thường.
  - Thay đổi quyền truy cập của các tệp tin và thư mục: Kẻ tấn công có thể sử dụng các công cụ như "chmod" để thay đổi quyền truy cập của các tệp tin và thư mục trên hệ thống.
  - Tạo tệp tin và thư mục mới: Kẻ tấn công có thể tạo các tệp tin và thư mục mới trên hệ thống và cấu hình sai quyền truy cập cho chúng.
  - Đọc các tệp tin chứa thông tin nhạy cảm: Kẻ tấn công có thể đọc các tệp tin chứa thông tin nhạy cảm như thông tin đăng nhập và mật khẩu.
  - Thực thi mã độc: Kẻ tấn công có thể tải lên và thực thi các mã độc trên hệ thống bằng cách sử dụng các tệp tin và thư mục có quyền truy cập không đúng.

- Từ các kĩ thuật được liệt kê ở trên, em sẽ cố gắng thực hiện 2 kĩ thuật đầu tiên

### Truy cập các tệp tin và thư mục bị cấu hình sai quyền truy cập (/etc/shadow)

- Theo chat-gpt:

```
- /etc/shadow là một tệp tin quan trọng chứa thông tin về các tài khoản người dùng và các mật khẩu được mã hóa. Tệp tin này chỉ có quyền truy cập cho người dùng root trên hệ thống.
- Thông tin về mật khẩu trong tệp tin /etc/shadow được mã hóa và bảo vệ bởi các thuật toán băm mạnh như SHA-512 hoặc bcrypt để ngăn chặn việc truy cập trái phép hoặc đánh cắp mật khẩu.
- Tệp tin /etc/shadow có cấu trúc dạng bảng và chứa các thông tin như tên người dùng, mã hóa mật khẩu,
```

- Thông qua một vài dòng tìm hiểu thì ta thấy ta có thể truy cập đến `/etc/shadow` để có được một số thông tin về mật khẩu, tên người dùng.

- Đây là lỗi phổ biến khi tạo server và không giới hạn quyền truy cập của user. Bây giờ chúng ta thử kiểm tra server của em, ở vai trò người dùng có thể có quyền truy cập `/etc/shadow`

- Ở đây em có user là hacklord, để trở thành vai trò root ta sử dụng lệnh `sudo su` và xoá quyền đọc cho hacklord

![image](https://user-images.githubusercontent.com/111769169/228819356-3487a82c-66fa-49d9-bd08-89c55d4af45c.png)

- Khi cat flag, ta thấy báo lỗi không có quyền, kể cả `sudo su` cũng bị giới hạn

![image](https://user-images.githubusercontent.com/111769169/228819630-6024d2b6-51b5-459f-b09c-fe26baaa5d34.png)

- Em cũng xoá cả quyền chmod của user bằng lệnh `sudo setfacl -m u:<username>:--- /bin/chmod (<username> là tên người dùng)`

#### Khai thác

- Đầu tiên ta xem quyền của `/etc/shadow`, ta có quyền read-write, do sơ xuất của root không giới hạn quyền truy cập

![image](https://user-images.githubusercontent.com/111769169/228821610-a454d553-3038-4f91-b979-eea86a049a9e.png)

- Sau khi `cat /etc/shadow` ta được những thông tin như:

```
root:$6$mHn5kRDq$gK7KeGJ6WOrxWsJh3gySDMk0RHor.YUOLMlqKbIj7i3HRnLhmSmQT.uFz6/JWatqpxpY/s2P.1nz1KgVnwf100:19446:0:99999:7:::
daemon:*:19121:0:99999:7:::
bin:*:19121:0:99999:7:::
sys:*:19121:0:99999:7:::
sync:*:19121:0:99999:7:::
games:*:19121:0:99999:7:::
man:*:19121:0:99999:7:::
lp:*:19121:0:99999:7:::
mail:*:19121:0:99999:7:::
news:*:19121:0:99999:7:::
uucp:*:19121:0:99999:7:::
proxy:*:19121:0:99999:7:::
www-data:*:19121:0:99999:7:::
backup:*:19121:0:99999:7:::
list:*:19121:0:99999:7:::
irc:*:19121:0:99999:7:::
gnats:*:19121:0:99999:7:::
nobody:*:19121:0:99999:7:::
systemd-network:*:19121:0:99999:7:::
systemd-resolve:*:19121:0:99999:7:::
syslog:*:19121:0:99999:7:::
messagebus:*:19121:0:99999:7:::
_apt:*:19121:0:99999:7:::
lxd:*:19121:0:99999:7:::
uuidd:*:19121:0:99999:7:::
dnsmasq:*:19121:0:99999:7:::
landscape:*:19121:0:99999:7:::
pollinate:*:19121:0:99999:7:::
test:$6$O80vVzBw$coie7alwY/TJH0BPBLJZeTsFcA5KG.Zz2DywxNHB67mZSw0cSLUpU.ChEjpCvtmusA2k/5BSYTT.r0XFxJplR1:19437:0:99999:7:::
sshd:*:19437:0:99999:7:::
hacklord:$6$vUGWj4l1$qA31OXE2NZkzyBH4G/3wFLPnlB/qKiR6fDXlEo7mnMSLjxUjcn7cDuTiB9Ii0FI6/Fk2/.ntj0himmU4Tm5Wc1:19446:0:99999:7:::
```

- Dòng đầu tiên chính là mật khẩu đã được mã hoá SHA-512 hash (là hàm một chiều, nghĩa là không thể giải mã)
- Do ta có quyền ghi nên ta có thể tạo mật khẩu của chúng ta, dùng SHA-512 hash để mã hoá và sau đó ghi vào file `/etc/shadow`
- Để tạo được một mật khẩu mới được mã hoá bằng SHA-512 ta dùng lệnh `mkpasswd -m sha-512 <newPassword>`sau đó ghi vào ở khoảng giữa 2 dấu ':'
- Nếu dòng đầu tiên ở giữa 2 dấu ":" là "*" thì nghĩa root chưa cài pass

![image](https://user-images.githubusercontent.com/111769169/228843099-2c5bb2aa-21a7-408e-9076-c8fcb5e02b04.png)

- Thực thi, ta tạo mật khẩu mới và mã hoá sha-512

![image](https://user-images.githubusercontent.com/111769169/228843473-b190b338-d93d-4430-a9bc-362a5504a9fa.png)

- Sau đó dùng nano hoặc vim để thay đổi đoạn này bằng đoạn ta vừa tạo, lưu lại.

![image](https://user-images.githubusercontent.com/111769169/228843099-2c5bb2aa-21a7-408e-9076-c8fcb5e02b04.png)

- Cuối cùng ta sẽ đăng nhập với vai trò là root `su root` khi được hỏi password ta nhập theo pass mới mà ta ghi đè (trường hợp của em là 1235)

![image](https://user-images.githubusercontent.com/111769169/228844576-5ff3a04f-3a1f-473c-a2e8-dfaba901e1c9.png)

#### Thay đổi quyền truy cập của các tệp tin và thư mục(chmod)

- Dùng chmod để thay đổi quyền của file sẽ khả thi nếu root không giới hạn quyền này ở user