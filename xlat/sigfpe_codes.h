/* Generated by ./xlat/gen.sh from ./xlat/sigfpe_codes.in; do not edit. */

static const struct xlat sigfpe_codes[] = {
#if defined(FPE_INTDIV) || (defined(HAVE_DECL_FPE_INTDIV) && HAVE_DECL_FPE_INTDIV)
	XLAT(FPE_INTDIV),
#endif
#if defined(FPE_INTOVF) || (defined(HAVE_DECL_FPE_INTOVF) && HAVE_DECL_FPE_INTOVF)
	XLAT(FPE_INTOVF),
#endif
#if defined(FPE_FLTDIV) || (defined(HAVE_DECL_FPE_FLTDIV) && HAVE_DECL_FPE_FLTDIV)
	XLAT(FPE_FLTDIV),
#endif
#if defined(FPE_FLTOVF) || (defined(HAVE_DECL_FPE_FLTOVF) && HAVE_DECL_FPE_FLTOVF)
	XLAT(FPE_FLTOVF),
#endif
#if defined(FPE_FLTUND) || (defined(HAVE_DECL_FPE_FLTUND) && HAVE_DECL_FPE_FLTUND)
	XLAT(FPE_FLTUND),
#endif
#if defined(FPE_FLTRES) || (defined(HAVE_DECL_FPE_FLTRES) && HAVE_DECL_FPE_FLTRES)
	XLAT(FPE_FLTRES),
#endif
#if defined(FPE_FLTINV) || (defined(HAVE_DECL_FPE_FLTINV) && HAVE_DECL_FPE_FLTINV)
	XLAT(FPE_FLTINV),
#endif
#if defined(FPE_FLTSUB) || (defined(HAVE_DECL_FPE_FLTSUB) && HAVE_DECL_FPE_FLTSUB)
	XLAT(FPE_FLTSUB),
#endif
	XLAT_END
};
