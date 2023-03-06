# phân tích

- Qua source ta thấy có BOF ở:

```c
    char buf1[100];
    gets(buf1);
```

và

```c
    char buf2[16];
    strcpy(buf2, input);
```

từ đây ta sẽ nhập hơn 16 kí tự để bof (bài này em chạy thấy lỗi nhưng nó lại nhảy hàm ```sigsegv_handler``` để thực thi =))))

```picoCTF{ov3rfl0ws_ar3nt_that_bad_a065d5d9}```
