// RUN: %clang_cc1 -analyze -analyzer-checker=magenta.SpinLock -verify %s
// expected-no-diagnostics

typedef unsigned int lock_t;

static lock_t l;

void spin_lock(lock_t *lock);
void spin_unlock(lock_t *lock);
int bar();

int foo() {
  int a = bar();
  if (a > 0) {
    spin_lock(&l);
  }

  if (a < -10) {
    spin_lock(&l);
  }

  if (a > 0)
    spin_unlock(&l);

  if (a < -10)
    spin_unlock(&l);

  return 0;
}

