// TODO: header template

#include "clang/Analysis/Analyses/OSLog.h"
#include "clang/AST/Attr.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/ExprObjC.h"
#include "clang/Analysis/Analyses/FormatString.h"
#include "clang/Basic/Builtins.h"
#include "llvm/ADT/SmallBitVector.h"

using namespace clang;
using llvm::APInt;

using clang::analyze_os_log::OSLogBufferItem;
using clang::analyze_os_log::OSLogBufferLayout;

class OSLogFormatStringHandler
    : public analyze_format_string::FormatStringHandler {
private:
  struct ArgData {
    const Expr *E = nullptr;
    Optional<OSLogBufferItem::Kind> Kind;
    Optional<unsigned> Size;
    unsigned char Flags = 0;
  };
  SmallVector<ArgData, 4> ArgsData;
  ArrayRef<const Expr *> Args;

  OSLogBufferItem::Kind
  getKind(analyze_format_string::ConversionSpecifier::Kind K) {
    switch (K) {
    case clang::analyze_format_string::ConversionSpecifier::sArg: // "%s"
      return OSLogBufferItem::StringKind;
    case clang::analyze_format_string::ConversionSpecifier::SArg: // "%S"
      return OSLogBufferItem::WideStringKind;
    case clang::analyze_format_string::ConversionSpecifier::PArg: { // "%P"
      return OSLogBufferItem::PointerKind;
    case clang::analyze_format_string::ConversionSpecifier::ObjCObjArg: // "%@"
      return OSLogBufferItem::ObjCObjKind;
    case clang::analyze_format_string::ConversionSpecifier::PrintErrno: // "%m"
      return OSLogBufferItem::ErrnoKind;
    default:
      return OSLogBufferItem::ScalarKind;
    }
    }
  }

public:
  OSLogFormatStringHandler(ArrayRef<const Expr *> Args) : Args(Args) {
    ArgsData.reserve(Args.size());
  }

  virtual bool HandlePrintfSpecifier(const analyze_printf::PrintfSpecifier &FS,
                                     const char *StartSpecifier,
                                     unsigned SpecifierLen) {
    if (!FS.consumesDataArgument() &&
        FS.getConversionSpecifier().getKind() !=
            clang::analyze_format_string::ConversionSpecifier::PrintErrno)
      return false;

    ArgsData.emplace_back();
    unsigned ArgIndex = FS.getArgIndex();
    if (ArgIndex < Args.size())
      ArgsData.back().E = Args[ArgIndex];

    // First get the Kind
    ArgsData.back().Kind = getKind(FS.getConversionSpecifier().getKind());
    if (ArgsData.back().Kind != OSLogBufferItem::ErrnoKind &&
        !ArgsData.back().E) {
      // missing argument
      ArgsData.pop_back();
      return false;
    }

    switch (FS.getConversionSpecifier().getKind()) {
    case clang::analyze_format_string::ConversionSpecifier::sArg:   // "%s"
    case clang::analyze_format_string::ConversionSpecifier::SArg: { // "%S"
      auto &precision = FS.getPrecision();
      switch (precision.getHowSpecified()) {
      case clang::analyze_format_string::OptionalAmount::NotSpecified: // "%s"
        break;
      case clang::analyze_format_string::OptionalAmount::Constant: // "%.16s"
        ArgsData.back().Size = precision.getConstantAmount();
        break;
      case clang::analyze_format_string::OptionalAmount::Arg: // "%.*s"
        ArgsData.back().Kind = OSLogBufferItem::CountKind;
        break;
      case clang::analyze_format_string::OptionalAmount::Invalid:
        return false;
      }
      break;
    }
    case clang::analyze_format_string::ConversionSpecifier::PArg: { // "%P"
      auto &precision = FS.getPrecision();
      switch (precision.getHowSpecified()) {
      case clang::analyze_format_string::OptionalAmount::NotSpecified: // "%P"
        return false; // length must be supplied with pointer format specifier
      case clang::analyze_format_string::OptionalAmount::Constant: // "%.16P"
        ArgsData.back().Size = precision.getConstantAmount();
        break;
      case clang::analyze_format_string::OptionalAmount::Arg: // "%.*P"
        ArgsData.back().Kind = OSLogBufferItem::CountKind;
        break;
      case clang::analyze_format_string::OptionalAmount::Invalid:
        return false;
      }
      break;
    }
    default:
      break;
    }

    if (FS.isPrivate()) {
      ArgsData.back().Flags |= OSLogBufferItem::IsPrivate;
    }
    if (FS.isPublic()) {
      ArgsData.back().Flags |= OSLogBufferItem::IsPublic;
    }
    return true;
  }

  void computeLayout(ASTContext &Ctx, OSLogBufferLayout &Layout) const {
    Layout.Items.clear();
    for (auto &Data : ArgsData) {
      if (Data.Size)
        Layout.Items.emplace_back(Ctx, CharUnits::fromQuantity(*Data.Size),
                                  Data.Flags);
      if (Data.Kind) {
        CharUnits Size;
        if (*Data.Kind == OSLogBufferItem::ErrnoKind)
          Size = CharUnits::Zero();
        else
          Size = Ctx.getTypeSizeInChars(Data.E->getType());
        Layout.Items.emplace_back(*Data.Kind, Data.E, Size, Data.Flags);
      } else {
        auto Size = Ctx.getTypeSizeInChars(Data.E->getType());
        Layout.Items.emplace_back(OSLogBufferItem::ScalarKind, Data.E, Size,
                                  Data.Flags);
      }
    }
  }
};

bool clang::analyze_os_log::computeOSLogBufferLayout(
    ASTContext &Ctx, const CallExpr *E, OSLogBufferLayout &Layout) {
  ArrayRef<const Expr *> Args(E->getArgs(), E->getArgs() + E->getNumArgs());

  const Expr *StringArg;
  ArrayRef<const Expr *> VarArgs;
  switch (E->getBuiltinCallee()) {
  case Builtin::BI__builtin_os_log_format_buffer_size:
    assert(E->getNumArgs() >= 1 &&
           "__builtin_os_log_format_buffer_size takes at least 1 argument");
    StringArg = E->getArg(0);
    VarArgs = Args.slice(1);
    break;
  case Builtin::BI__builtin_os_log_format:
    assert(E->getNumArgs() >= 2 &&
           "__builtin_os_log_format takes at least 2 arguments");
    StringArg = E->getArg(1);
    VarArgs = Args.slice(2);
    break;
  default:
    llvm_unreachable("non-os_log builtin passed to computeOSLogBufferLayout");
  }

  const StringLiteral *Lit = cast<StringLiteral>(StringArg->IgnoreParenCasts());
  assert(Lit && (Lit->isAscii() || Lit->isUTF8()));
  StringRef Data = Lit->getString();
  OSLogFormatStringHandler H(VarArgs);
  ParsePrintfString(H, Data.begin(), Data.end(), Ctx.getLangOpts(),
                    Ctx.getTargetInfo(), /*isFreeBSDKPrintf*/ false);

  H.computeLayout(Ctx, Layout);
  return true;
}
