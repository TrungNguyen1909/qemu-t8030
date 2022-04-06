all: sock_fuzz

sock_fuzz: sock_fuzz.c fuzz.S fuzz.h
    xcrun -sdk iphoneos clang -arch arm64 -o sock_fuzz sock_fuzz.c fuzz.S
    codesign -f -s - --entitlements ent.xml sock_fuzz
