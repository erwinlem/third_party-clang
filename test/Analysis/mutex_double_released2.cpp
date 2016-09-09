// RUN: %clang_cc1 -analyze -analyzer-checker=magenta.MutexChecker -verify %s

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
  void release() { mutex_release(&m); } // expected-warning{{Found an execution path where an unacquired mutex is released}}
  ~Mutex() { mutex_destroy(&m); }
};

int f();

class Test {
  Mutex lock;
 public:
  Test() { }
  void action();
  ~Test() { }
};

void Test::action() {
  int x = f();
  if (x > 10)
    lock.acquire();

  if (x > 10)
    lock.release();

  lock.release();
}

int main() {
  Test testClass;
  testClass.action();
  return 0;
}
