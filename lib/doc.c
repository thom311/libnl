/*
 * lib/doc.c		Documentation Purpose
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
 */

/**
 * @mainpage
 *
 * @section remarks Remarks
 *
 * @subsection cache_alloc Allocation of Caches
 *
 * Almost all subsystem provide a function to allocate a new cache
 * of some form. The function usually looks like this:
 * @code
 * struct nl_cache *<object name>_alloc_cache(struct nl_handle *handle)
 * @endcode
 *
 * These functions allocate a new cache for the own object type,
 * initializes it properly and updates it to represent the current
 * state of their master, e.g. a link cache would include all
 * links currently configured in the kernel.
 *
 * Some of the allocation functions may take additional arguments
 * to further specify what will be part of the cache.
 *
 * All such functions return a newly allocated cache or NULL
 * in case of an error.
 *
 * @subsection addr Setting of Addresses
 * @code
 * int <object name>_set_addr(struct nl_object *, struct nl_addr *)
 * @endcode
 *
 * All attribute functions avaiable for assigning addresses to objects
 * take a struct nl_addr argument. The provided address object is
 * validated against the address family of the object if known already.
 * The assignment fails if the address families mismatch. In case the
 * address family has not been specified yet, the address family of
 * the new address is elected to be the new requirement.
 *
 * The function will acquire a new reference on the address object
 * before assignment, the caller is NOT responsible for this.
 *
 * All functions return 0 on success or a negative error code.
 *
 * @subsection flags Flags to Character StringTranslations
 * All functions converting a set of flags to a character string follow
 * the same principles, therefore, the following information applies
 * to all functions convertings flags to a character string and vice versa.
 *
 * @subsubsection flags2str Flags to Character String
 * @code
 * char *<object name>_flags2str(int flags, char *buf, size_t len)
 * @endcode
 * @arg flags		Flags.
 * @arg buf		Destination buffer.
 * @arg len		Buffer length.
 *
 * Converts the specified flags to a character string separated by
 * commas and stores it in the specified destination buffer.
 *
 * @return The destination buffer
 *
 * @subsubsection str2flags Character String to Flags
 * @code
 * int <object name>_str2flags(const char *name)
 * @endcode
 * @arg name		Name of flag.
 *
 * Converts the provided character string specifying a flag
 * to the corresponding numeric value.
 *
 * @return Link flag or a negative value if none was found.
 *
 * @subsubsection type2str Type to Character String
 * @code
 * char *<object name>_<type>2str(int type, char *buf, size_t len)
 * @endcode
 * @arg type		Type as numeric value
 * @arg buf		Destination buffer.
 * @arg len		Buffer length.
 *
 * Converts an identifier (type) to a character string and stores
 * it in the specified destination buffer.
 *
 * @return The destination buffer or the type encoded in hexidecimal
 *         form if the identifier is unknown.
 *
 * @subsubsection str2type Character String to Type
 * @code
 * int <object name>_str2<type>(const char *name)
 * @endcode
 * @arg name		Name of identifier (type).
 *
 * Converts the provided character string specifying a identifier
 * to the corresponding numeric value.
 *
 * @return Identifier as numeric value or a negative value if none was found.
 */
