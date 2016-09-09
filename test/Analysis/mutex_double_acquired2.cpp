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
  void acquire() { mutex_acquire(&m); } // expected-warning{{Found an execution path where a destroyed/acquired mutex is taken}}

  void release() { mutex_release(&m); } // expected-warning{{Found an execution path where an unacquired mutex is released}}

  ~Mutex() { mutex_destroy(&m); }
};

int f();

class Hidden {
  Mutex m;
 public:
  Hidden() {}
  ~Hidden() {}
  void action();
};

void Hidden::action() {
  int x = f();
  if (x > 10)
    m.acquire();

  if (x > 25)
    m.acquire();
  m.release();
}

class Test {
 public:
  Test() { Hidden h; h.action(); }
  void action();
  ~Test() { }
};
