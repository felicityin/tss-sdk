# Install

https://studygolang.com/articles/19679

https://www.cnblogs.com/ghj1976/p/gomobile-pei-zhi-peng-dao-de-wen-ti-ji-lu.html

https://githubwyb.github.io/blogs/2022-05-24-gomobile/

```
go get golang.org/x/mobile/bind
```

# Build

```
gomobile init

gomobile bind -target=android .

# 27 is version
# ls Android/Sdk/ndk/
# 27.0.11718014
# gomobile bind -androidapi 27 -target=android .

# gomobile bind -target=ios .
```
