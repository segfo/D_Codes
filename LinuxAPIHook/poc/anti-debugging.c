#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/ptrace.h>
// ptrace anti-debugging
int main(){
  int isDebugging = ptrace(PTRACE_TRACEME,0,1,0) == -1;
  if(isDebugging){
      printf("is debugging!\n");
  }else{
      printf("not debugging.\nrun process.\n");
  }
  return 0;
}
