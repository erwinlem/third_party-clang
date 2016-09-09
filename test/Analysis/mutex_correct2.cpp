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
  Mutex m;
 public:
  Test() { }
  void action();
  ~Test() { }
};

void Test::action() {
  int x = f();

  if (x > 10)
    m.acquire();
  else
    m.acquire();

  if (x > 10)
    m.release();
  else
    m.release();
}

void mutHandler() {
  Mutex mut1;
  mutex_t mut2;
  mutex_init(&mut2);
  mut1.acquire();
  mutex_acquire(&mut2);
  f();
  mutex_release(&mut2);
  mut1.release();
  mutex_destroy(&mut2);
}
