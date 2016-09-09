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
  void release() { mutex_release(&m); }
  ~Mutex() { mutex_destroy(&m); }
};

int f();

class Test {
  mutex_t lock;
 public:
  Test() { mutex_init(&lock); }
  void action();
  ~Test() { mutex_destroy(&lock); }
};

void Test::action() {
  int x = f();
  if (x > 10)
    mutex_acquire(&lock);

  if (x > 25)
    mutex_acquire(&lock); // expected-warning{{Found an execution path where a destroyed/acquired mutex is taken}}

  mutex_release(&lock); // expected-warning{{Found an execution path where an unacquired mutex is released}}
}

int main() {
  Test testClass;
  testClass.action();
  return 0;
}

