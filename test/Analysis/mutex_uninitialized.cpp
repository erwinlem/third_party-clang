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

class Test {
  mutex_t lock;
 public:
  Test() { }
  void action() { }
  ~Test() { mutex_destroy(&lock); } // expected-warning{{Mutex was not initialized in the constructor}}
};

int main()
{
  Test testClass;
  return 0;
}
