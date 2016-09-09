// RUN: %clang_cc1 -analyze -analyzer-checker=magenta.MutexChecker -verify %s
// expected-no-diagnostics

struct mutex_t {
    unsigned int count;
};

void mutex_init(mutex_t *);
void mutex_acquire(mutex_t *);
void mutex_release(mutex_t *);
void mutex_destroy(mutex_t *);

class Mutex {
  mutex_t m;
 public:
  Mutex() { mutex_init(&m); }
  void acquire() { mutex_acquire(&m); }
  void release() { mutex_release(&m); }
  ~Mutex() { mutex_destroy(&m); }
};

int f();

class Test {
  mutex_t lock1;
  mutex_t lock2;
 public:
  Test() { mutex_init(&lock1); mutex_init(&lock2);}
  void action();
  ~Test() { mutex_destroy(&lock1); mutex_destroy(&lock2); }
};

void Test::action() {
  int x = f();

  if (x > 10)
    mutex_acquire(&lock1);
  else
    mutex_acquire(&lock2);

  if (x > 10)
    mutex_release(&lock1);
  else
    mutex_release(&lock2);
}
