//== SpinLockChecker.cpp - SpinLock checker ---------------------*- C++ -*--==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This defines SpinLockChecker, a check for Magenta Kernel to make sure
// there are no execution paths were spinlocks are locked twice in a row,
// or unlocked twice in a row.
//
//===----------------------------------------------------------------------===//

#include "ClangSACheckers.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "llvm/ADT/SmallString.h"

using namespace clang;
using namespace ento;

namespace {

typedef llvm::SmallString<16> ErrorCategoryStr;
typedef llvm::SmallString<32> FunctionNameStr;

struct LockInfo {

  enum Kind { Locked, Released } K;

  LockInfo(Kind kind) : K(kind) {}

  bool operator==(const LockInfo &LI) const { return K == LI.K; }

  void Profile(llvm::FoldingSetNodeID &ID) const { ID.AddInteger(K); }

  bool isLocked() const { return K == Locked; }

  bool isReleased() const { return K == Released; }

  static LockInfo getLocked() { return LockInfo(Locked); }

  static LockInfo getReleased() { return LockInfo(Released); }

  static ErrorCategoryStr getLockErrorCategory() { return LockErrCategory; }

  static FunctionNameStr getSpinLockFuncName() { return SpinLockFuncName; }

  static FunctionNameStr getSpinUnlockFuncName() { return SpinUnlockFuncName; }

private:
  static const ErrorCategoryStr LockErrCategory;
  static const FunctionNameStr SpinLockFuncName;
  static const FunctionNameStr SpinUnlockFuncName;
};

const ErrorCategoryStr LockInfo::LockErrCategory("Lock Error");
const FunctionNameStr LockInfo::SpinLockFuncName("spin_lock");
const FunctionNameStr LockInfo::SpinUnlockFuncName("spin_unlock");
}

/// We keep track of the locks in a map. SpinLockMap, maps the
/// memory region of a spinlock to its status (locked, released).
/// The reason that we keep track of spinlocks as memory region is
/// that the lock/unlock functions take lock arguments as pointers.
REGISTER_MAP_WITH_PROGRAMSTATE(SpinLockMap, const MemRegion *, LockInfo)

namespace {

class SpinLockChecker : public Checker<check::PreCall> {

  /// When facing a spin_unlock function call, check the record of the
  /// corresponding lock in SpinLockMap and make sure that there are no
  /// problems such as double unlocks.
  void processSpinUnlockCall(const CallEvent &Call, CheckerContext &C,
                             const MemRegion *SpinLockLocation) const;

  /// When facing a spin_lock function call, check the record of the
  /// corresponding lock in SpinLockMap and make sure that there are no
  /// problems such as double locks.
  void processSpinLockCall(const CallEvent &Call, CheckerContext &C,
                           const MemRegion *SpinLockLocation) const;
  void reportDoubleLock(const CallEvent &Call, CheckerContext &C,
                        const MemRegion *Mem) const;
  void reportDoubleUnlock(ExplodedNode *Node, CheckerContext &C,
                          const MemRegion *Mem) const;
  std::unique_ptr<BugType> DoubleLockBugType;
  std::unique_ptr<BugType> DoubleUnlockBugType;

public:
  SpinLockChecker();
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};
}

void ento::registerSpinLockChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<SpinLockChecker>();
}

SpinLockChecker::SpinLockChecker() {
  DoubleLockBugType.reset(
      new BugType(this, "Double SpinLock", LockInfo::getLockErrorCategory()));

  DoubleUnlockBugType.reset(
      new BugType(this, "Double SpinUnlock", LockInfo::getLockErrorCategory()));
}

/// Run the necessary processing before a spin_lock/spin_unlock function call
void SpinLockChecker::checkPreCall(const CallEvent &Call,
                                   CheckerContext &C) const {
  FunctionNameStr CalleeName = Call.getCalleeIdentifier()->getName();
  if (CalleeName != LockInfo::getSpinLockFuncName() &&
      CalleeName != LockInfo::getSpinUnlockFuncName())
    return;

  // Memory region of the spinlock
  const MemRegion *SpinLockLocation = Call.getArgSVal(0).getAsRegion();
  // If SpinLocLocation is NULL, this is likely due to changes in the signature
  // of spin_lock/spin_unlock functions, and we have to update the checker
  // accordingly. For now, we terminate with an error message.
  if (!SpinLockLocation)
    llvm_unreachable("No spinlock pointer passed to spin_lock/spin_unlock!");

  if (CalleeName == LockInfo::getSpinLockFuncName())
    processSpinLockCall(Call, C, SpinLockLocation);
  else
    processSpinUnlockCall(Call, C, SpinLockLocation);
}

void SpinLockChecker::processSpinLockCall(
    const CallEvent &Call, CheckerContext &C,
    const MemRegion *SpinLockLocation) const {
  ProgramStateRef St = C.getState();
  const LockInfo *LI = St->get<SpinLockMap>(SpinLockLocation);
  if (LI && LI->isLocked()) {
    // This spinlock has been locked before!
    reportDoubleLock(Call, C, SpinLockLocation);
    return;
  }

  St = St->set<SpinLockMap>(SpinLockLocation, LockInfo::getLocked());
  C.addTransition(St);
}

void SpinLockChecker::processSpinUnlockCall(
    const CallEvent &Call, CheckerContext &C,
    const MemRegion *SpinLockLocation) const {
  ProgramStateRef St = C.getState();
  const LockInfo *LI = St->get<SpinLockMap>(SpinLockLocation);
  if (LI && LI->isReleased()) {
    // Unlocking a key twice! Does not cause an error, but may be an
    // indication of an incorrect logic (maybe the spinlock was supposed to
    // be locked again before the second unlocking attempt).
    ExplodedNode *Node = C.generateNonFatalErrorNode(St);
    reportDoubleUnlock(Node, C, SpinLockLocation);
  }

  St = St->set<SpinLockMap>(SpinLockLocation, LockInfo::getReleased());
  C.addTransition(St);
}

void SpinLockChecker::reportDoubleUnlock(
    ExplodedNode *Node, CheckerContext &C,
    const MemRegion *SpinLockLocation) const {
  auto Report = llvm::make_unique<BugReport>(
      *DoubleUnlockBugType,
      "Execution path found where spinlock is unlocked twice in a row", Node);
  Report->markInteresting(SpinLockLocation);
  C.emitReport(std::move(Report));
}

void SpinLockChecker::reportDoubleLock(
    const CallEvent &Call, CheckerContext &C,
    const MemRegion *SpinLockLocation) const {
  ExplodedNode *Node = C.generateErrorNode();
  if (!Node)
    return;

  auto Report = llvm::make_unique<BugReport>(
      *DoubleLockBugType,
      "Execution path found where spinlock is locked twice in a row", Node);
  Report->addRange(Call.getSourceRange());
  Report->markInteresting(SpinLockLocation);
  C.emitReport(std::move(Report));
}
