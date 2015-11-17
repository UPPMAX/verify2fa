
all: libpam_verify2fa.so
  

libpam_verify2fa.so: pam_verify2fa.c
	gcc -fPIC -o libpam_verify2fa.so -shared pam_verify2fa.c -lpam -lcurl

