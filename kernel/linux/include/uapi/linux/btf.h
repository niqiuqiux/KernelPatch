
#ifndef _KP_BTF_H_
#define _KP_BTF_H_

#include <ktypes.h>

#define __u32 uint32_t
#define __u8 uint8_t

#define BTF_MAGIC 0xeB9F
#define BTF_VERSION 1

/* BTF头部结构 */
struct btf_header {
	uint16_t	magic;
	uint8_t	version;
	uint8_t	flags;
	uint32_t	hdr_len;
	uint32_t	type_off;	/* offset of type section	*/
	uint32_t	type_len;	/* length of type section	*/
	uint32_t	str_off;	/* offset of string section	*/
	uint32_t	str_len;	/* length of string section	*/
};

/* Max # of type identifier */
#define BTF_MAX_TYPE	0x000fffff
/* Max offset into the string section */
#define BTF_MAX_NAME_OFFSET	0x00ffffff
/* Max # of struct/union/enum members or func args */
#define BTF_MAX_VLEN	0xffff

/* BTF类型结构 */
struct btf_type {
	__u32 name_off;
	/* "info" bits arrangement
	 * bits  0-15: vlen (e.g. # of struct's members)
	 * bits 16-23: unused
	 * bits 24-28: kind (e.g. int, ptr, array...etc)
	 * bits 29-30: unused
	 * bit     31: kind_flag, currently used by
	 *             struct, union, enum, fwd and enum64
	 */
	__u32 info;
	/* "size" is used by INT, ENUM, STRUCT, UNION, DATASEC and ENUM64.
	 * "size" tells the size of the type it is describing.
	 *
	 * "type" is used by PTR, TYPEDEF, VOLATILE, CONST, RESTRICT,
	 * FUNC, FUNC_PROTO, VAR, DECL_TAG and TYPE_TAG.
	 * "type" is a type_id referring to another type.
	 */
	union {
		__u32 size;
		__u32 type;
	};
};

#define BTF_INFO_KIND(info)	(((info) >> 24) & 0x1f)
#define BTF_INFO_VLEN(info)	((info) & 0xffff)
#define BTF_INFO_KFLAG(info)	((info) >> 31)

enum {
	BTF_KIND_UNKN		= 0,	/* Unknown	*/
	BTF_KIND_INT		= 1,	/* Integer	*/
	BTF_KIND_PTR		= 2,	/* Pointer	*/
	BTF_KIND_ARRAY		= 3,	/* Array	*/
	BTF_KIND_STRUCT		= 4,	/* Struct	*/
	BTF_KIND_UNION		= 5,	/* Union	*/
	BTF_KIND_ENUM		= 6,	/* Enumeration up to 32-bit values */
	BTF_KIND_FWD		= 7,	/* Forward	*/
	BTF_KIND_TYPEDEF	= 8,	/* Typedef	*/
	BTF_KIND_VOLATILE	= 9,	/* Volatile	*/
	BTF_KIND_CONST		= 10,	/* Const	*/
	BTF_KIND_RESTRICT	= 11,	/* Restrict	*/
	BTF_KIND_FUNC		= 12,	/* Function	*/
	BTF_KIND_FUNC_PROTO	= 13,	/* Function Proto	*/
	BTF_KIND_VAR		= 14,	/* Variable	*/
	BTF_KIND_DATASEC	= 15,	/* Section	*/
	BTF_KIND_FLOAT		= 16,	/* Floating point	*/
	BTF_KIND_DECL_TAG	= 17,	/* Decl Tag */
	BTF_KIND_TYPE_TAG	= 18,	/* Type Tag */
	BTF_KIND_ENUM64		= 19,	/* Enumeration up to 64-bit values */

	NR_BTF_KINDS,
	BTF_KIND_MAX		= NR_BTF_KINDS - 1,
};

/* For some specific BTF_KIND, "struct btf_type" is immediately
 * followed by extra data.
 */

/* BTF_KIND_INT is followed by a u32 and the following
 * is the 32 bits arrangement:
 */
#define BTF_INT_ENCODING(VAL)	(((VAL) & 0x0f000000) >> 24)
#define BTF_INT_OFFSET(VAL)	(((VAL) & 0x00ff0000) >> 16)
#define BTF_INT_BITS(VAL)	((VAL)  & 0x000000ff)

/* Attributes stored in the BTF_INT_ENCODING */
#define BTF_INT_SIGNED	(1 << 0)
#define BTF_INT_CHAR	(1 << 1)
#define BTF_INT_BOOL	(1 << 2)

/* BTF_KIND_ENUM is followed by multiple "struct btf_enum".
 * The exact number of btf_enum is stored in the vlen (of the
 * info in "struct btf_type").
 */
struct btf_enum {
	__u32	name_off;
	int32_t	val;
};

/* BTF_KIND_ARRAY is followed by one "struct btf_array" */
struct btf_array {
	__u32	type;
	__u32	index_type;
	__u32	nelems;
};

/* BTF_KIND_STRUCT and BTF_KIND_UNION are followed
 * by multiple "struct btf_member".  The exact number
 * of btf_member is stored in the vlen (of the info in
 * "struct btf_type").
 */
struct btf_member {
	__u32	name_off;
	__u32	type;
	/* If the type info kind_flag is set, the btf_member offset
	 * contains both member bitfield size and bit offset. The
	 * bitfield size is set for bitfield members. If the type
	 * info kind_flag is not set, the offset contains only bit
	 * offset.
	 */
	__u32	offset;
};

/* If the struct/union type info kind_flag is set, the
 * following two macros are used to access bitfield_size
 * and bit_offset from btf_member.offset.
 */
#define BTF_MEMBER_BITFIELD_SIZE(val)	((val) >> 24)
#define BTF_MEMBER_BIT_OFFSET(val)	((val) & 0xffffff)

/* BTF_KIND_FUNC_PROTO is followed by multiple "struct btf_param".
 * The exact number of btf_param is stored in the vlen (of the
 * info in "struct btf_type").
 */
struct btf_param {
	__u32	name_off;
	__u32	type;
};

enum {
	BTF_VAR_STATIC = 0,
	BTF_VAR_GLOBAL_ALLOCATED = 1,
	BTF_VAR_GLOBAL_EXTERN = 2,
};

enum btf_func_linkage {
	BTF_FUNC_STATIC = 0,
	BTF_FUNC_GLOBAL = 1,
	BTF_FUNC_EXTERN = 2,
};

/* BTF_KIND_VAR is followed by a single "struct btf_var" to describe
 * additional information related to the variable such as its linkage.
 */
struct btf_var {
	__u32	linkage;
};

/* BTF_KIND_DATASEC is followed by multiple "struct btf_var_secinfo"
 * to describe all BTF_KIND_VAR types it contains along with it's
 * in-section offset as well as size.
 */
struct btf_var_secinfo {
	__u32	type;
	__u32	offset;
	__u32	size;
};

/* BTF_KIND_DECL_TAG is followed by a single "struct btf_decl_tag" to describe
 * additional information related to the tag applied location.
 * If component_idx == -1, the tag is applied to a struct, union,
 * variable or function. Otherwise, it is applied to a struct/union
 * member or a func argument, and component_idx indicates which member
 * or argument (0 ... vlen-1).
 */
struct btf_decl_tag {
    int   component_idx;
};

/* BTF_KIND_ENUM64 is followed by multiple "struct btf_enum64".
 * The exact number of btf_enum64 is stored in the vlen (of the
 * info in "struct btf_type").
 */
struct btf_enum64 {
	__u32	name_off;
	__u32	val_lo32;
	__u32	val_hi32;
};

/* BTF对象 */
typedef struct
{
    const char *data;              /* BTF数据在内核虚拟地址空间的指针 */
    uint32_t data_size;            /* BTF数据大小 */
    struct btf_header *hdr;        /* BTF头部指针（指向data） */
    const struct btf_type **types; /* 类型指针数组（动态分配） */
    const char *strings;           /* 字符串表指针（指向data） */
    uint32_t nr_types;            /* 类型数量 */
} btf_t;

/* BTF类型信息 */
typedef struct
{
    uint32_t type_id;
    uint32_t kind;
    const char *name;
    uint32_t size;
    void *type_data;
} btf_type_info_t;

/* BTF结构体成员信息 */
typedef struct
{
    const char *name;
    uint32_t type_id;
    uint32_t offset;
    uint32_t bit_offset;
    uint32_t bitfield_size;
} btf_member_info_t;

/* BTF枚举值信息 */
typedef struct
{
    const char *name;
    int32_t val;
} btf_enum_info_t;

/* BTF枚举64值信息 */
typedef struct
{
    const char *name;
    uint64_t val;
} btf_enum64_info_t;

/* BTF 变量信息 */
typedef struct
{
    const char *name;       /* 变量名 */
    uint32_t type_id;       /* 变量的类型 ID（即 VAR->type 指向的类型） */
    uint32_t size;          /* 变量类型大小（字节） */
    uint32_t linkage;       /* BTF_VAR_STATIC / BTF_VAR_GLOBAL_ALLOCATED / BTF_VAR_GLOBAL_EXTERN */
} btf_var_info_t;

/* BTF 数组信息 */
typedef struct
{
    uint32_t type_id;       /* 数组元素类型 ID */
    uint32_t index_type_id; /* 数组索引类型 ID */
    uint32_t nelems;        /* 数组元素数量 */
} btf_array_info_t;

/* BTF 函数参数信息 */
typedef struct
{
    const char *name;       /* 参数名（可能为 NULL） */
    uint32_t type_id;       /* 参数类型 ID */
} btf_param_info_t;

/* BTF 整数类型编码信息 */
typedef struct
{
    uint32_t encoding;      /* BTF_INT_ENCODING 值 */
    uint32_t offset;        /* BTF_INT_OFFSET 值 */
    uint32_t bits;         /* BTF_INT_BITS 值 */
    bool is_signed;        /* 是否为有符号整数 */
    bool is_char;          /* 是否为字符类型 */
    bool is_bool;          /* 是否为布尔类型 */
} btf_int_info_t;

/* 从内核虚拟地址空间解析BTF */
int32_t btf_parse(btf_t *btf);
void btf_free(btf_t *btf);

const struct btf_type *btf_type_by_id(const btf_t *btf, uint32_t type_id);
const char *btf_name_by_offset(const btf_t *btf, uint32_t name_off);
uint32_t btf_kind(const struct btf_type *t);
uint32_t btf_vlen(const struct btf_type *t);

int32_t btf_get_type_info(const btf_t *btf, uint32_t type_id, btf_type_info_t *info);
int32_t btf_find_by_name(const btf_t *btf, const char *name);
int32_t btf_find_by_name_kind(const btf_t *btf, const char *name, uint32_t kind);

/* 根据类型 ID 获取最终类型大小（自动跳过 typedef/修饰符），仅对有 size 的类型有效 */
int32_t btf_get_type_size_by_id(const btf_t *btf, uint32_t type_id, uint32_t *size_out);

/* 根据结构体名称获取结构体大小（支持 typedef 包装的结构体） */
int32_t btf_get_struct_size(const btf_t *btf, const char *struct_name, uint32_t *size_out);

/* 根据 VAR 类型 ID 获取内核变量信息（名称 / 类型 / 大小 / linkage） */
int32_t btf_get_var_info_by_id(const btf_t *btf, uint32_t var_type_id, btf_var_info_t *info);

/* 根据变量名获取内核变量信息（内部自动查找 BTF_KIND_VAR） */
int32_t btf_get_var_info_by_name(const btf_t *btf, const char *var_name, btf_var_info_t *info);

int32_t btf_get_struct_members(const btf_t *btf, uint32_t struct_type_id, btf_member_info_t *members, int32_t max_members);
int32_t btf_get_enum_values(const btf_t *btf, uint32_t enum_type_id, btf_enum_info_t *values, int32_t max_values);
int32_t btf_get_enum64_values(const btf_t *btf, uint32_t enum_type_id, btf_enum64_info_t *values, int32_t max_values);

/* 根据数组类型 ID 获取数组信息（元素类型、索引类型、元素数量） */
int32_t btf_get_array_info(const btf_t *btf, uint32_t array_type_id, btf_array_info_t *info);

/* 根据指针类型 ID 获取指针指向的目标类型 ID */
int32_t btf_get_ptr_target_type_id(const btf_t *btf, uint32_t ptr_type_id, uint32_t *target_type_id);

/* 根据函数原型类型 ID 获取函数参数信息 */
int32_t btf_get_func_proto_params(const btf_t *btf, uint32_t func_proto_type_id, btf_param_info_t *params, int32_t max_params);

/* 根据函数原型类型 ID 获取函数返回类型 ID */
int32_t btf_get_func_proto_return_type_id(const btf_t *btf, uint32_t func_proto_type_id, uint32_t *return_type_id);

/* 根据整数类型 ID 获取整数编码信息 */
int32_t btf_get_int_info(const btf_t *btf, uint32_t int_type_id, btf_int_info_t *info);

/* 类型遍历回调函数类型 */
typedef int (*btf_type_iter_cb_t)(const btf_t *btf, uint32_t type_id, const struct btf_type *t, void *ctx);

/* 遍历所有类型，对每个类型调用回调函数 */
int32_t btf_iterate_types(const btf_t *btf, btf_type_iter_cb_t callback, void *ctx);

/* 根据名称前缀查找类型（返回第一个匹配的类型 ID） */
int32_t btf_find_by_name_prefix(const btf_t *btf, const char *prefix);

/* 根据名称前缀和 kind 查找类型 */
int32_t btf_find_by_name_prefix_kind(const btf_t *btf, const char *prefix, uint32_t kind);


/* 通过结构体 type_id + 成员名查找成员信息（offset/type_id 等） */
int32_t btf_find_struct_member_by_type_id(const btf_t *btf,
                                          uint32_t struct_type_id,
                                          const char *member_name,
                                          btf_member_info_t *out);

/* 通过结构体名称 + 成员名查找成员信息 */
int32_t btf_find_struct_member(const btf_t *btf,
                               const char *struct_name,
                               const char *member_name,
                               btf_member_info_t *out);

/* 结构体多级成员路径解析结果 */
typedef struct
{
    uint32_t final_type_id;   /* 最终成员的类型 ID */
    uint32_t final_offset;    /* 相对于最外层结构体的总字节偏移 */
} btf_member_path_result_t;

/* 按结构体 type_id + 路径（形如 "a.b.c"）解析嵌套成员的最终 offset/type */
int32_t btf_resolve_member_path_by_type_id(const btf_t *btf,
                                           uint32_t root_type_id,
                                           const char *path,
                                           btf_member_path_result_t *out);

/* 按结构体名 + 路径（形如 "a.b.c"）解析嵌套成员的最终 offset/type */
int32_t btf_resolve_member_path(const btf_t *btf,
                                const char *struct_name,
                                const char *path,
                                btf_member_path_result_t *out);

#endif /* _KP_BTF_H_ */

