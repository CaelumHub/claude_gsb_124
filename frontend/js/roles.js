/* ================================================================
   roles.js —— 全前端统一的角色判定(与 backend/auth.py 一一对应)

   规则唯一来源, editor / mindmap / chat / permissions 各页面都只
   引用这里的判定, 避免某页把「可评论」误当成「可编辑」之类的分叉。

   角色高低: owner > editor > commenter > viewer
     viewer    可见(查看白板/历史/导出/聊天记录)
     commenter viewer + 协作聊天发言
     editor    commenter + 绘制编辑画布/撤销重做/存缩略图
     owner     editor + 成员权限/公开角色/删除白板/压缩历史

   判定优先级(有效角色, 由服务端 board_role 下发):
     系统管理员 > 白板所有者 > 成员授权 acl > 邀请链接默认角色 > 拒绝
   ================================================================ */

export const ROLE_ORDER = { viewer: 1, commenter: 2, editor: 3, owner: 4 };

export const ROLE_LABEL = {
  owner: '所有者',
  editor: '可编辑',
  commenter: '可评论',
  viewer: '只读',
};

export function roleAtLeast(role, required) {
  return (ROLE_ORDER[role] || 0) >= (ROLE_ORDER[required] || 99);
}

/** 用户名内部键: 与后端 canonical_username 相同 —— 去空格 + 小写。 */
export function canonicalUsername(name) {
  return String(name || '').trim().toLowerCase();
}

export const canView = (role) => roleAtLeast(role, 'viewer');
export const canComment = (role) => roleAtLeast(role, 'commenter');
export const canEdit = (role) => roleAtLeast(role, 'editor');
export const canManage = (role) => roleAtLeast(role, 'owner');

/**
 * 与后端 auth.board_role 同逻辑的本地预演(权限页「有效性预览」用)。
 * @param {{role?: string}} user          当前用户(全局角色在 user.role)
 * @param {{owner?: string, acl?: Object, public_role?: string|null}} meta
 * @param {string} username               要预演的用户名(任意大小写)
 * @returns {{role: string|null, step: number}}
 */
export function effectiveRole(user, meta, username) {
  const key = canonicalUsername(username);
  const ownerKey = canonicalUsername(meta?.owner);
  const acl = meta?.acl || {};
  // acl 的键在服务端也是 canonical, 这里同时兼容原始/小写两种键
  const aclRole = acl[key] ?? acl[username] ?? null;
  if (user?.role === 'admin' && canonicalUsername(user.username) === key) {
    return { role: 'owner', step: 1 };
  }
  if (ownerKey && ownerKey === key) return { role: 'owner', step: 2 };
  if (aclRole) return { role: aclRole, step: 3 };
  if (meta?.public_role) return { role: meta.public_role, step: 4 };
  return { role: null, step: 5 };
}
