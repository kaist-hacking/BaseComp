#include <stdio.h>
void baz() {
  printf("Hello baz");
}

void bar() {
  printf("Hello, bar");
  baz();
}

void foo() {
  printf("Hello, foo");
  bar();
}

int main() {
  foo();
}
