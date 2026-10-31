#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include "libiberty.h"
__attribute__((noinline)) static int nested(unsigned char tag) {
  unsigned char *p=alloca(512);memset(p,tag,512);
  for(int i=0;i<512;i++)if(p[i]!=tag)return 1;return 0;
}
static void *worker(void *arg) {
  unsigned char tag=(unsigned long)arg;char word[32];
  memset(word,tag,31);word[31]=0;
  for(int i=0;i<1000;i++) {
    unsigned char *p=alloca(127);memset(p,tag,127);
    char *s=ASTRDUP(word);if(nested(tag))return (void*)1;
    for(int j=0;j<127;j++)if(p[j]!=tag)return (void*)1;
    if(strcmp(s,word))return (void*)1;
  }return 0;
}
int main(int argc,char **argv) {
  if(argc>1){void *p=C_alloca((size_t)-1);return p?2:3;}
  pthread_t a,b;void *x,*y;
  if(pthread_create(&a,0,worker,(void*)65)||pthread_create(&b,0,worker,(void*)66))return 4;
  pthread_join(a,&x);pthread_join(b,&y);return x||y;
}
