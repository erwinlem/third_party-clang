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
class Hidden {
  Mutex m;
  mutex_t m2;
 public:
  Hidden() { mutex_init(&m2); }
  ~Hidden() { mutex_destroy(&m2); }
  void action();
};

void Hidden::action() {
  int x = f();
  if (x > 10)
    m.acquire();

  if (x > 10)
    m.release();
}

class Test {
  mutex_t m;
 public:
  Test() { Hidden h; h.action(); mutex_init(&m); } // expected-warning{{Mutex was not destroyed in the destructor}}
  void action();
  ~Test() { }
};
