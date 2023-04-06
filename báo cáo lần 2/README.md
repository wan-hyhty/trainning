# Linux Privilege Escalation - Part 1

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
- Nếu dòng đầu tiên ở giữa 2 dấu ":" là "\*" thì nghĩa root chưa cài pass

![image](https://user-images.githubusercontent.com/111769169/228843099-2c5bb2aa-21a7-408e-9076-c8fcb5e02b04.png)

- Thực thi, ta tạo mật khẩu mới và mã hoá sha-512

![image](https://user-images.githubusercontent.com/111769169/228843473-b190b338-d93d-4430-a9bc-362a5504a9fa.png)

- Sau đó dùng nano hoặc vim để thay đổi đoạn này bằng đoạn ta vừa tạo, lưu lại.

![image](https://user-images.githubusercontent.com/111769169/228843099-2c5bb2aa-21a7-408e-9076-c8fcb5e02b04.png)

- Cuối cùng ta sẽ đăng nhập với vai trò là root `su root` khi được hỏi password ta nhập theo pass mới mà ta ghi đè (trường hợp của em là 1235)

![image](https://user-images.githubusercontent.com/111769169/228844576-5ff3a04f-3a1f-473c-a2e8-dfaba901e1c9.png)

#### Writable /etc/passwd

##### /etc/passwd là gì ?

- Trong hệ thống Linux, tập tin /etc/passwd là một tập tin văn bản lưu trữ thông tin về các tài khoản người dùng trên hệ thống.
- Tên tài khoản, Mật khẩu,...
- Lổ hổng này là do root không giới hạn quyền write vào `/etc/passwd`, khi đó kẻ xấu có thể ghi đè giá trị hash của mật khẩu thành hash của mật khẩu của kẻ trộm

##### Khai thác

- Thông thường, `/etc/passwd` mặc định là không có quyền write nhưng nếu ta có thể lên được các vị trí cao hơn trong server để thay đổi quyền.
- Ở đây ta sẽ tạo một ví dụ là root quên giới hạn quyền write cho user nên ta có thể thay đổi được giá trị hash của mật khẩu được lưu trong file

- Mặc định ở 3 chỗ cuối chúng ta sẽ không có quyền w, nhưng ở đây ta sẽ set quyền w cho user
  ![image](https://user-images.githubusercontent.com/111769169/230270541-f5c7cbed-9cdf-409f-9056-39c0d786cf5b.png)

- Đầu tiên ta sẽ tạo một hash `từ chữ sang hash` bằng lệnh `mkpasswd`
- Ở đây em sẽ tạo một pass abcd có chuỗi hash là `$1$r4iS7BSh$3Thjzf0Eq0w5WzlXuhi.L1` (ta không cần thiết chạy trên server, có thể chạy trên máy của mình)
- Sau đó ta chú ý trong `/etc/passwd`, pass của chúng ta đã được mã hoá là `x`, ta sẽ ghi đè hash của chúng ta vào đó

![image](https://user-images.githubusercontent.com/111769169/230271929-80b19f66-fa16-40ab-b3bc-20a1bab103ae.png)

![image](https://user-images.githubusercontent.com/111769169/230272170-8eb2ce61-911a-45f4-b984-d253a347f398.png)

- Vậy là ta có thể sử dụng pass (ở đây là abcd) để đăng nhập với vai trò là root

![image](https://user-images.githubusercontent.com/111769169/230272380-930d6e9e-fef4-4d88-b5da-7dc6d440f51d.png)

#### Sudo Rights with Iftop, More, less, ftp, man

- Đây là những lệnh ta có thể dùng để có được quyền sudo
- Trong trường hợp này, việc giới hạn quyền khá khó khăn, cho nên mặc định chúng ta sẽ có thể sử dụng tất cả các quyền. (trong ctf sẽ bị hạn chế quyền)
- dùng `sudo -l` để kiểm tra ta có thể sử dụng quyền gì

![image](https://user-images.githubusercontent.com/111769169/230274156-3e98d135-454a-4ce5-8d19-f0452a8db6cf.png)

- Trên thực tế, ta chỉ được sử dụng các quyền này
  ![image](https://user-images.githubusercontent.com/111769169/230274274-802d6d90-9aeb-4cdb-b11d-1296ca5bfde9.png)

###### iftop

> bài này em không chạy được, có thể họ đã tắt chức năng này rồi

- Server phải được cài các iftop
- chạy lệnh `sudo /usr/sbin/iftop`
- Giao diện của iftop như này

![image](https://user-images.githubusercontent.com/111769169/230276056-5e30087e-7e31-4877-903a-dfb96f72d8d5.png)

- Ta sẽ giữ `shift+1` thì giao diện sẽ như này, nhập vào sh và enter

![image](https://user-images.githubusercontent.com/111769169/230276493-5236c9a3-a9e3-41c6-a52e-0f99c13a866a.png)

![image](https://user-images.githubusercontent.com/111769169/230276637-4f68cbe2-94e8-4df8-a82c-b0f35f141f86.png)

###### less

- /usr/bin/less là một chương trình dòng lệnh trong Linux được sử dụng để xem nội dung của một tập tin văn bản dài. Nó cho phép bạn xem và đọc các tập tin lớn mà không cần phải tải toàn bộ tập tin vào bộ nhớ, giúp tiết kiệm tài nguyên hệ thống.
- và nó có shell command để ta thực hiện chiếm shell
- Chạy lệnh `sudo /usr/bin/less /etc/passwd`

![image](https://user-images.githubusercontent.com/111769169/230277507-6e84aa8f-c346-40c1-a630-1355bfe3e4d1.png)

- Ta giữ `shift + 1` và gõ `sh`

![image](https://user-images.githubusercontent.com/111769169/230277714-796542a5-0696-4366-8b13-808d9c0d0470.png)

![image](https://user-images.githubusercontent.com/111769169/230277803-8f1f3423-b04b-44f1-b035-39b47817d7ee.png)

###### more

- /bin/more là một chương trình dòng lệnh trong Linux được sử dụng để xem nội dung của một tập tin văn bản dài. Nó cho phép bạn xem và đọc các tập tin lớn một trang một lần, giúp tránh hiện tượng quá tải bộ nhớ.
- Tiếp tục một hướng khai thác tương tự như less, do nó có thể thực thi shell command
- Chạy lệnh `sudo /bin/more /etc/passwd`
- ở đây more nó sẽ in ra màn hình, nếu phần văn bản không in ra hết nó sẽ để more như này
  ![image](https://user-images.githubusercontent.com/111769169/230278694-cb3fe57e-443b-4ba9-bda5-c68e364cf259.png)
- Cho nên nếu để màn hình quá lớn, văn bản sẽ được in ra hết và không có chữ more để ta thực thi shell
- Vậy ta sẽ thu nhỏ màn lại và chạy lệnh trên
  ![image](https://user-images.githubusercontent.com/111769169/230278933-3c200dc7-6388-4934-bd4c-0d9e1f0a51d7.png)
- Và tiếp tục là `!sh`

  ![image](https://user-images.githubusercontent.com/111769169/230279040-ae8dcbcb-37bc-4464-9baf-b5439fc5aa3f.png)

  ![image](https://user-images.githubusercontent.com/111769169/230279181-781ef731-b3a0-4723-8c1d-06b77960f597.png)

##### Chú ý

- Nếu kiểm tra các lệnh có thể sử dụng mà có lệnh less hoặc more, ta nên thử dùng less (more) để đọc thử file flag.txt
  ![image](https://user-images.githubusercontent.com/111769169/230279533-36eb3660-682c-4d85-b78e-0640842b498f.png)

###### man

- `man` là một tiện ích trong hệ điều hành Linux được sử dụng để hiển thị hướng dẫn sử dụng cho các lệnh, các tập tin cấu hình, các gói phần mềm, các hàm thư viện và các tài liệu khác trên hệ thống. Man được viết tắt từ Manual (sách hướng dẫn) và là một phần quan trọng của hệ thống Linux.
- `man` khi in ra văn bản quá dài sẽ có chữ `more` (phần văn bản chưa in hết), do đó cách khai thác tương tự như `more`

![image](https://user-images.githubusercontent.com/111769169/230280137-bfa5e140-ee98-4f32-abf5-f1e313922895.png)

- Ta sử dụng lệnh `sudo man ls` hoặc `sudo /usr/bin/man ls`

![image](https://user-images.githubusercontent.com/111769169/230280745-1dcddf99-7db5-4c2e-8174-4f720e5cca86.png)

![image](https://user-images.githubusercontent.com/111769169/230280643-29093afd-a548-481a-9461-4f427174ce4b.png)

###### ftp

- Trong Linux, FTP có thể được sử dụng để truyền tải tập tin giữa các máy tính trên mạng bằng cách sử dụng một chương trình FTP như ftp hoặc sftp trong terminal.

  ![image](https://user-images.githubusercontent.com/111769169/230285007-84d7e6d7-e8b0-44c1-a328-1c1d1c56e75f.png)
