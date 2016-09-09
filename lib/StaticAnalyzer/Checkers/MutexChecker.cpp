//== MutexChecker.cpp - Mutex checker ---------------------------*- C++ -*--==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This defines MutexChecker for Magenta Kernel. MutexChecker makes sure
// that mutexes are only released after being acquired, and are not acquired
// twice in a row by the same thread. Also it makes sure that the mutexes
// initialized and destroyed during the construction and destruction of an
// object, match.
//
//===----------------------------------------------------------------------===//

#include "ClangSACheckers.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "llvm/ADT/StringSwitch.h"

using namespace clang;
using namespace ento;

namespace {

struct MutexInfo {

  enum Kind { Initialized, Acquired, Released, Destroyed } K;

  MutexInfo(Kind kind) : K(kind) {}

  bool operator==(const MutexInfo &LI) const { return K == LI.K; }

  void Profile(llvm::FoldingSetNodeID &ID) const { ID.AddInteger(K); }

  bool isInitialized() const { return K == Initialized; }

  bool isAcquired() const { return K == Acquired; }

  bool isReleased() const { return K == Released; }

  bool isDestroyed() const { return K == Destroyed; }

  static MutexInfo getInitialized() { return MutexInfo(Initialized); }

  static MutexInfo getAcquired() { return MutexInfo(Acquired); }

  static MutexInfo getReleased() { return MutexInfo(Released); }

  static MutexInfo getDestroyed() { return MutexInfo(Destroyed); }
};
}

/// Keeps track of the state of each mutex during an execution path.
REGISTER_MAP_WITH_PROGRAMSTATE(MutexMap, const MemRegion *, MutexInfo)

namespace {

class MutexChecker : public Checker<check::PreCall, check::EndFunction> {
  typedef std::set<std::string> MutexSet;
  typedef std::map<std::string, MutexSet> ClassToMutexMap;
  typedef void (MutexChecker::*MutexProcessingFn)(const CallEvent &,
                                                  CheckerContext &,
                                                  const MemRegion *) const;

  mutable std::map<std::string, bool> ConstructorProcessed;
  mutable std::map<std::string, bool> DestructorProcessed;
  mutable ClassToMutexMap InitializedSet;
  mutable ClassToMutexMap DestroyedSet;

  void processMutexInitCall(const CallEvent &Call, CheckerContext &C,
                            const MemRegion *SpinLockLocation) const;

  /// When facing a mutex_acquire function call, check the record of the
  /// corresponding mutex in MutexMap and make sure that there are no
  /// problems. For example, the mutex has to be already initialized at this
  /// point.
  void processMutexAcquireCall(const CallEvent &Call, CheckerContext &C,
                               const MemRegion *SpinLockLocation) const;

  /// When facing a mutex_release function call, check the record of the
  /// corresponding mutex in MutexMap and make sure that there are no
  /// problems. For example, the mutex has to be already acquired at this point.
  void processMutexReleaseCall(const CallEvent &Call, CheckerContext &C,
                               const MemRegion *SpinLockLocation) const;

  /// When facing a mutex_destroy function call, check the record of the
  /// corresponding mutex in MutexMap and make sure that there are no
  /// problems. For example, the mutex should not be acquired.
  void processMutexDestroyCall(const CallEvent &Call, CheckerContext &C,
                               const MemRegion *SpinLockLocation) const;

  void reportMutexError(CheckerContext &C, const MemRegion *MutexMemRegion,
                        StringRef ErrMsg, bool Fatal) const;

  /// Make sure the initialized and destroyed mutexes in the constructor and
  /// destructor match.
  void analyzeInitializedAndDestroyedMutexes(CheckerContext &C) const;

  /// We do not analyze the implementation of the Mutex class itself. We rather
  /// analyze the use of Mutex APIs in other parts of the code. Therefore, we
  /// consider Mutex class an exception in our analysis and ignore it.
  bool isException(const MemRegion *MutexMemRegion) const;

  /// Helper function to find out if the current function is type T.
  /// T could be constructor, destructor, CXXMethod, etc.
  template <class T> bool isFunctionType(const Decl *D) const;

  /// Helper function to find out if we are in the context of function type T.
  /// T could be constructor, destructor, CXXMethod, etc.
  template <class T> bool isInContextOfFuncType(CheckerContext &C) const;

  /// Find the class name from the current context.
  std::string getClassName(CheckerContext &C) const;

  std::unique_ptr<BugType> MutexBugType;

public:
  MutexChecker();
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkEndFunction(CheckerContext &C) const;
};
}

void ento::registerMutexChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<MutexChecker>();
}

MutexChecker::MutexChecker() {
  MutexBugType.reset(new BugType(this, "Mutex error", "Lock Error"));
}

bool MutexChecker::isException(const MemRegion *MutexMemRegion) const {
  // In this function, to detect if the analyzer is analyzing the
  // Mutex class, we take advantage of the fact that in this situation
  // the SuperRegion that includes the memory region of mutex_t object
  // included in Mutex class is of kind SymbolicMemoryRegionKind.
  if (MutexMemRegion->getKind() != MemRegion::FieldRegionKind)
    return false;

  const FieldRegion *FR = dyn_cast<FieldRegion>(MutexMemRegion);
  if (!FR)
    return false;

  const FieldDecl *FDecl = FR->getDecl();
  if (!FDecl)
    return false;

  // if mutex_t is a member of a class other than Mutex, we want to
  // analyze the class.
  const RecordDecl *RDecl = FDecl->getParent();
  if (!RDecl || RDecl->getNameAsString() != "Mutex")
    return false;

  const SubRegion *SubR = dyn_cast<SubRegion>(MutexMemRegion);
  if (!SubR)
    return false;

  const MemRegion *SuperR = SubR->getSuperRegion();
  if (!SuperR)
    return false;

  return SuperR->getKind() == MemRegion::SymbolicRegionKind;
}

void MutexChecker::checkPreCall(const CallEvent &Call,
                                CheckerContext &C) const {

  if (!Call.getCalleeIdentifier())
    return;

  std::string CalleeName = Call.getCalleeIdentifier()->getName();

  if (CalleeName != "mutex_init" && CalleeName != "mutex_acquire" &&
      CalleeName != "mutex_release" && CalleeName != "mutex_destroy")
    return;

  if (Call.getNumArgs() == 0)
    return;

  // Memory region of the mutex
  const MemRegion *MutexMemRegion = Call.getArgSVal(0).getAsRegion();
  // If SpinLocLocation is NULL, this is likely due to changes in the signature
  // of mutex functions.
  if (!MutexMemRegion) {
    llvm_unreachable("No mutex pointer passed to mutex_acquire/mutex_release!");
  }

  // If it is the exception case, no need to perform analysis.
  if (isException(MutexMemRegion))
    return;

  MutexProcessingFn ProcessMutexCall =
      llvm::StringSwitch<MutexProcessingFn>(CalleeName)
          .Case("mutex_init", &MutexChecker::processMutexInitCall)
          .Case("mutex_acquire", &MutexChecker::processMutexAcquireCall)
          .Case("mutex_release", &MutexChecker::processMutexReleaseCall)
          .Case("mutex_destroy", &MutexChecker::processMutexDestroyCall);

  (this->*ProcessMutexCall)(Call, C, MutexMemRegion);
}

void MutexChecker::processMutexInitCall(const CallEvent &Call,
                                        CheckerContext &C,
                                        const MemRegion *MutexMemRegion) const {
  ProgramStateRef St = C.getState();

  // Gather all the init calls in the constructor.
  if (isInContextOfFuncType<CXXConstructorDecl>(C)) {
    std::string CurrClass = getClassName(C);
    if (!ConstructorProcessed[CurrClass])
      InitializedSet[CurrClass].insert(MutexMemRegion->getString());
  }

  const MutexInfo *LI = St->get<MutexMap>(MutexMemRegion);
  if (LI)
    // Initializing a mutex after being used! report a bug
    reportMutexError(
        C, MutexMemRegion,
        "Found an execution path where mutex is being initialized after use",
        false);

  St = St->set<MutexMap>(MutexMemRegion, MutexInfo::getInitialized());
  C.addTransition(St);
}

void MutexChecker::processMutexAcquireCall(
    const CallEvent &Call, CheckerContext &C,
    const MemRegion *MutexMemRegion) const {
  ProgramStateRef St = C.getState();
  const MutexInfo *LI = St->get<MutexMap>(MutexMemRegion);
  if (LI && (LI->isAcquired() || LI->isDestroyed()))
    // Mutex cannot be acquired if it is acquired before, or after it is
    // destroyed
    reportMutexError(
        C, MutexMemRegion,
        "Found an execution path where a destroyed/acquired mutex is taken",
        false);

  St = St->set<MutexMap>(MutexMemRegion, MutexInfo::getAcquired());
  C.addTransition(St);
}

void MutexChecker::processMutexReleaseCall(
    const CallEvent &Call, CheckerContext &C,
    const MemRegion *MutexMemRegion) const {
  ProgramStateRef St = C.getState();
  const MutexInfo *LI = St->get<MutexMap>(MutexMemRegion);
  if (!LI)
    // This is the first time this mutex is being used, and it is not
    // initialized.
    reportMutexError(
        C, MutexMemRegion,
        "Found an execution path where an uninitialized mutex is used", false);
  else if (!LI->isAcquired())
    // Releasing a mutex that is not acquired.
    reportMutexError(
        C, MutexMemRegion,
        "Found an execution path where an unacquired mutex is released", false);

  St = St->set<MutexMap>(MutexMemRegion, MutexInfo::getReleased());
  C.addTransition(St);
}

void MutexChecker::processMutexDestroyCall(
    const CallEvent &Call, CheckerContext &C,
    const MemRegion *MutexMemRegion) const {
  ProgramStateRef St = C.getState();
  // Gather all the destroy calls in the destructor.
  if (isInContextOfFuncType<CXXDestructorDecl>(C)) {
    std::string CurrClass = getClassName(C);
    if (!DestructorProcessed[CurrClass])
      DestroyedSet[CurrClass].insert(MutexMemRegion->getString());
  }

  St = St->set<MutexMap>(MutexMemRegion, MutexInfo::getDestroyed());
  C.addTransition(St);
}

void MutexChecker::reportMutexError(CheckerContext &C,
                                    const MemRegion *MutexMemRegion,
                                    StringRef ErrMsg, bool Fatal) const {
  ExplodedNode *Node;
  if (Fatal)
    Node = C.generateErrorNode();
  else
    Node = C.generateNonFatalErrorNode(C.getState());
  if (!Node)
    return;
  auto Report = llvm::make_unique<BugReport>(*MutexBugType, ErrMsg, Node);
  if (MutexMemRegion)
    Report->markInteresting(MutexMemRegion);
  C.emitReport(std::move(Report));
}

template <class T> bool MutexChecker::isFunctionType(const Decl *D) const {
  if (!D)
    return false;

  if (const FunctionDecl *FD = dyn_cast<FunctionDecl>(D))
    return isa<T>(FD);

  return false;
}

std::string MutexChecker::getClassName(CheckerContext &C) const {
  std::string Name = "";
  const LocationContext *LC = C.getLocationContext();
  while (LC && !isFunctionType<CXXMethodDecl>(LC->getDecl()))
    LC = LC->getParent();

  if (LC) {
    const CXXMethodDecl *MDecl = dyn_cast<CXXMethodDecl>(LC->getDecl());
    Name = MDecl->getParent()->getNameAsString();
  }

  return Name;
}

template <class T>
bool MutexChecker::isInContextOfFuncType(CheckerContext &C) const {
  const LocationContext *LC = C.getLocationContext();
  while (LC && !isFunctionType<T>(LC->getDecl()))
    LC = LC->getParent();

  if (LC)
    return true;

  return false;
}

void MutexChecker::checkEndFunction(CheckerContext &C) const {
  // Unset flags if we are leaving constructor/destructor
  ExplodedNode *Node = C.getPredecessor();
  if (!Node)
    return;

  bool ExitingConstructor =
      isFunctionType<CXXConstructorDecl>(&Node->getCodeDecl());
  bool ExitingDestructor =
      isFunctionType<CXXDestructorDecl>(&Node->getCodeDecl());

  if (!ExitingConstructor && !ExitingDestructor)
    return;

  std::string CurrClass = getClassName(C);
  if (!CurrClass.size())
    return;

  // We have already done the processing, nothing left to do
  if (DestructorProcessed[CurrClass] && ConstructorProcessed[CurrClass])
    return;

  if (ExitingConstructor)
    ConstructorProcessed[CurrClass] = true;

  if (ExitingDestructor)
    DestructorProcessed[CurrClass] = true;

  // If this is the first time both constructor and destructor are processed,
  // compare initialized and destroyed mutexes
  if (DestructorProcessed[CurrClass] && ConstructorProcessed[CurrClass])
    analyzeInitializedAndDestroyedMutexes(C);
}

void MutexChecker::analyzeInitializedAndDestroyedMutexes(
    CheckerContext &C) const {
  std::string CurrClass = getClassName(C);
  for (auto I = InitializedSet[CurrClass].begin(),
            End = InitializedSet[CurrClass].end();
       I != End; ++I) {
    std::string InitLoc = *I;
    if (!DestroyedSet[CurrClass].count(InitLoc))
      reportMutexError(C, NULL, "Mutex was not destroyed in the destructor",
                       false);
  }

  for (auto I = DestroyedSet[CurrClass].begin(),
            End = DestroyedSet[CurrClass].end();
       I != End; ++I) {
    std::string DestroyedLoc = *I;
    if (!InitializedSet[CurrClass].count(DestroyedLoc))
      reportMutexError(C, NULL, "Mutex was not initialized in the constructor",
                       false);
  }
}
