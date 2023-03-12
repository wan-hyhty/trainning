# khai thác
ở đây ta thấy lỗi FMT
```c
    puts("Here's a story - ");
    printf(format);
```
và flag nó được lưu trong stack nên ta có thể dùng %p để leak flag ra
do là file 32bit nên ta sẽ đếm từ đầu stack đến flag là 36

vậy ta leak đến khi ra hết chuỗi và có thể dùng cyberchef để đổi hex sang ascii