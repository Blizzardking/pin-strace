/* Generated by ./xlat/gen.sh from ./xlat/inotify_flags.in; do not edit. */

static const struct xlat inotify_flags[] = {
#if defined(IN_ACCESS) || (defined(HAVE_DECL_IN_ACCESS) && HAVE_DECL_IN_ACCESS)
	XLAT(IN_ACCESS),
#endif
#if defined(IN_MODIFY) || (defined(HAVE_DECL_IN_MODIFY) && HAVE_DECL_IN_MODIFY)
	XLAT(IN_MODIFY),
#endif
#if defined(IN_ATTRIB) || (defined(HAVE_DECL_IN_ATTRIB) && HAVE_DECL_IN_ATTRIB)
	XLAT(IN_ATTRIB),
#endif
#if defined(IN_CLOSE) || (defined(HAVE_DECL_IN_CLOSE) && HAVE_DECL_IN_CLOSE)
	XLAT(IN_CLOSE),
#endif
#if defined(IN_CLOSE_WRITE) || (defined(HAVE_DECL_IN_CLOSE_WRITE) && HAVE_DECL_IN_CLOSE_WRITE)
	XLAT(IN_CLOSE_WRITE),
#endif
#if defined(IN_CLOSE_NOWRITE) || (defined(HAVE_DECL_IN_CLOSE_NOWRITE) && HAVE_DECL_IN_CLOSE_NOWRITE)
	XLAT(IN_CLOSE_NOWRITE),
#endif
#if defined(IN_OPEN) || (defined(HAVE_DECL_IN_OPEN) && HAVE_DECL_IN_OPEN)
	XLAT(IN_OPEN),
#endif
#if defined(IN_MOVE) || (defined(HAVE_DECL_IN_MOVE) && HAVE_DECL_IN_MOVE)
	XLAT(IN_MOVE),
#endif
#if defined(IN_MOVED_FROM) || (defined(HAVE_DECL_IN_MOVED_FROM) && HAVE_DECL_IN_MOVED_FROM)
	XLAT(IN_MOVED_FROM),
#endif
#if defined(IN_MOVED_TO) || (defined(HAVE_DECL_IN_MOVED_TO) && HAVE_DECL_IN_MOVED_TO)
	XLAT(IN_MOVED_TO),
#endif
#if defined(IN_CREATE) || (defined(HAVE_DECL_IN_CREATE) && HAVE_DECL_IN_CREATE)
	XLAT(IN_CREATE),
#endif
#if defined(IN_DELETE) || (defined(HAVE_DECL_IN_DELETE) && HAVE_DECL_IN_DELETE)
	XLAT(IN_DELETE),
#endif
#if defined(IN_DELETE_SELF) || (defined(HAVE_DECL_IN_DELETE_SELF) && HAVE_DECL_IN_DELETE_SELF)
	XLAT(IN_DELETE_SELF),
#endif
#if defined(IN_MOVE_SELF) || (defined(HAVE_DECL_IN_MOVE_SELF) && HAVE_DECL_IN_MOVE_SELF)
	XLAT(IN_MOVE_SELF),
#endif
#if defined(IN_UNMOUNT) || (defined(HAVE_DECL_IN_UNMOUNT) && HAVE_DECL_IN_UNMOUNT)
	XLAT(IN_UNMOUNT),
#endif
#if defined(IN_Q_OVERFLOW) || (defined(HAVE_DECL_IN_Q_OVERFLOW) && HAVE_DECL_IN_Q_OVERFLOW)
	XLAT(IN_Q_OVERFLOW),
#endif
#if defined(IN_IGNORED) || (defined(HAVE_DECL_IN_IGNORED) && HAVE_DECL_IN_IGNORED)
	XLAT(IN_IGNORED),
#endif
#if defined(IN_ONLYDIR) || (defined(HAVE_DECL_IN_ONLYDIR) && HAVE_DECL_IN_ONLYDIR)
	XLAT(IN_ONLYDIR),
#endif
#if defined(IN_DONT_FOLLOW) || (defined(HAVE_DECL_IN_DONT_FOLLOW) && HAVE_DECL_IN_DONT_FOLLOW)
	XLAT(IN_DONT_FOLLOW),
#endif
#if defined(IN_EXCL_UNLINK) || (defined(HAVE_DECL_IN_EXCL_UNLINK) && HAVE_DECL_IN_EXCL_UNLINK)
	XLAT(IN_EXCL_UNLINK),
#endif
#if defined(IN_MASK_ADD) || (defined(HAVE_DECL_IN_MASK_ADD) && HAVE_DECL_IN_MASK_ADD)
	XLAT(IN_MASK_ADD),
#endif
#if defined(IN_ISDIR) || (defined(HAVE_DECL_IN_ISDIR) && HAVE_DECL_IN_ISDIR)
	XLAT(IN_ISDIR),
#endif
#if defined(IN_ONESHOT) || (defined(HAVE_DECL_IN_ONESHOT) && HAVE_DECL_IN_ONESHOT)
    { static_cast<int>(IN_ONESHOT), "IN_ONESHOT" },
#endif
	XLAT_END
};
