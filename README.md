# libEZRadius 2.0

کتابخانه‌ی RADIUS (کلاینت، سرور و CoA/Disconnect) روی **netRector**. تمام کارهای شبکه async و non-blocking است و روی یک reactor اجرا می‌شود؛ **بدون thread، mutex و فراخوانی blocking**. وابستگی به Wrench حذف شده است.

پروتکل‌ها: RFC 2865، RFC 2866، RFC 3579 (Message-Authenticator و محافظت در برابر BlastRADIUS)، RFC 5176 (CoA و Disconnect) و Vendor-Specific attributeها (مثلاً MikroTik با شناسه‌ی 14988).

## ساخت

```
git clone https://github.com/crazyfull/netRector third_party/netRector   # یا -DEZRADIUS_NETRECTOR_DIR=<path> یا -DEZRADIUS_FETCH_NETRECTOR=ON
cmake -S . -B build -G Ninja -DNETRECTOR_ENABLE_TLS=OFF                    # -DEZRADIUS_SANITIZE=ON برای ASan و UBSan
cmake --build build && (cd build && ctest --output-on-failure)
```

در پروژه‌ی خودتان: `add_subdirectory(libezradius)` و `target_link_libraries(app PRIVATE EZRadius)`.

## کلاینت (async)

```cpp
netrector::EpollReactor reactor(0, 1024);
EZClientSettings s;
s.Host = "radius.example.com";   // آدرس IPv4 یا نام میزبان (DNS به‌صورت async resolve می‌شود)
s.Secret = "...";
s.TimeOut = 1500;                // میلی‌ثانیه برای هر تلاش
s.RetryCount = 3;                // تعداد کل تلاش‌ها

EZRadiusClient c(&reactor, s);
c.AddAttribute(USER_NAME, "user");
c.AddAttribute(USER_PASSWORD, "pass");   // PAP؛ برای CHAP از CHAP_PASSWORD استفاده کنید
c.Send(C_ACCESS_REQUEST, [](EZRadiusClient &c, EZResult r){
    if(r == EZResult::OK && c.GetResponseType() == ACCESS_ACCEPT) { /* ... */ }
});
reactor.run(stop);
```

- `Send()` بلافاصله برمی‌گردد و نتیجه (`OK`، `TIMEOUT`، `DNS_FAILED`، `SEND_FAILED`، `CANCELED`) با callback از داخل reactor می‌آید.
- retry و timeout با تایمر reactor انجام می‌شود. هر درخواست socket و source port تصادفی خودش را دارد.
- پاسخ فقط وقتی پذیرفته می‌شود که ID و Response Authenticator (و در صورت وجود یا الزام، Message-Authenticator) درست باشد.
- هر شیء یک درخواست را انجام می‌دهد؛ برای درخواست جدید `Reset()` را صدا بزنید.

## سرور

```cpp
EZRadiusServer server(&reactor);
server.RASList()->AddRAS("secret", "10.0.0.1");
server.SeRequestCallback(onRequest, nullptr);
server.Start();
```

پکت نامعتبر، RAS ناشناخته و Request Authenticator یا Message-Authenticator اشتباه قبل از رسیدن به callback دور ریخته می‌شوند.

ساخت پاسخ:

```cpp
EZResponse r;
r.AddAttribute(REPLY_MESSAGE, "welcome");
r.AddVendorAttribute(14988, 8, "10M/10M");   // MikroTik Rate-Limit
r.Send(ACCESS_ACCEPT, &from);
```

## CoA و Disconnect

```cpp
EZCoA coa(&reactor, settings);
coa.SetGetRequests(callback, nullptr);
coa.Start();
```

`Host` و `RAS_IP` در تنظیمات، آدرس‌های مجاز برای ارسال درخواست هستند.

## قواعد استفاده

- همه‌چیز فقط از thread مربوط به reactor استفاده شود؛ از threadهای دیگر با `reactor.post()`.
- شیءهای client، server و CoA باید قبل از reactor (یا قبل از پایان `run()`) از بین بروند.
- رمزها در لاگ چاپ نمی‌شوند (برای debug: `RadiusAttribute::setDumpPasswords(true)`).

## تست‌ها

- `test_packet`: تست واحد (شامل بردارهای RFC 2202 و RFC 2865 بخش 7.1)
- `test_loopback`: سرور، کلاینت و CoA روی یک reactor
- `fuzz_packet`: fuzz ساده‌ی parser پکت
