// RUN: %clang_cc1 -analyze -analyzer-checker=magenta.SpinLock -verify %s

typedef unsigned int lock_t;

typedef struct S {
  int a;
  lock_t l;
} S_t;

static S_t st;

void spin_lock(lock_t *lock);
void spin_unlock(lock_t *lock);
int bar();

void bar1(lock_t *y) {
  spin_unlock(y);
}

void bar2(lock_t *x) {
  spin_unlock(x); // expected-warning{{Execution path found where spinlock is unlocked twice in a row}}
}

int foo() {
  int a = bar();
  if (a > 0) {
    spin_lock(&st.l);
    bar1(&st.l);
  }

  lock_t *c = &st.l;
  bar2(c);
  return 0;
}

