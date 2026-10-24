export function createMockSupabase(initial = {}) {
  const profiles = new Map((initial.profiles || []).map(p => [p.id, { ...p }]));
  const documents = new Map((initial.documents || []).map(d => [d.id, { ...d }]));
  const permissions = new Map((initial.permissions || []).map(p => [`${p.document_id}:${p.user_id}`, { ...p }]));
  const auditEvents = [...(initial.auditEvents || [])];
  const storageObjects = new Map((initial.storage || []).map(s => [s.path, { ...s }]));

  function getTableData(table) {
    if (table === 'profiles') return profiles;
    if (table === 'documents') return documents;
    if (table === 'document_permissions') return permissions;
    return null;
  }

  function createQueryBuilder(table) {
    let operation = 'select';
    let insertData = null;
    let updateData = null;
    let upsertData = null;
    let filters = [];
    let orderCol = null;
    let orderAsc = true;
    let limitCount = null;

    const builder = {
      select(fields) {
        return builder;
      },
      eq(col, val) {
        filters.push(row => row[col] === val);
        return builder;
      },
      in(col, vals) {
        const set = new Set(vals);
        filters.push(row => set.has(row[col]));
        return builder;
      },
      ilike(col, pattern) {
        const clean = pattern.replaceAll('%', '').toLowerCase();
        filters.push(row => String(row[col] || '').toLowerCase().includes(clean));
        return builder;
      },
      gte(col, val) {
        filters.push(row => row[col] >= val);
        return builder;
      },
      lte(col, val) {
        filters.push(row => row[col] <= val);
        return builder;
      },
      order(col, { ascending = true } = {}) {
        orderCol = col;
        orderAsc = ascending;
        return builder;
      },
      limit(n) {
        limitCount = n;
        return builder;
      },
      insert(data) {
        operation = 'insert';
        insertData = data;
        return builder;
      },
      update(data) {
        operation = 'update';
        updateData = data;
        return builder;
      },
      upsert(data) {
        operation = 'upsert';
        upsertData = data;
        return builder;
      },
      delete() {
        operation = 'delete';
        return builder;
      },
      async execute() {
        if (table === 'audit_events') {
          if (operation === 'insert') {
            const row = { id: auditEvents.length + 1, created_at: new Date().toISOString(), ...insertData };
            auditEvents.push(row);
            return { data: row, error: null };
          }
          let rows = [...auditEvents];
          for (const f of filters) rows = rows.filter(f);
          if (orderCol) {
            rows.sort((a, b) => (a[orderCol] > b[orderCol] ? (orderAsc ? 1 : -1) : (orderAsc ? -1 : 1)));
          }
          if (limitCount) rows = rows.slice(0, limitCount);
          return { data: rows, error: null };
        }

        const map = getTableData(table);
        if (!map) return { data: null, error: new Error(`Unknown table ${table}`) };

        if (operation === 'insert') {
          const item = {
            id: insertData.id || crypto.randomUUID(),
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
            ...insertData
          };
          const key = table === 'document_permissions' ? `${item.document_id}:${item.user_id}` : item.id;
          map.set(key, item);
          return { data: item, error: null };
        }

        if (operation === 'upsert') {
          const key = table === 'document_permissions' ? `${upsertData.document_id}:${upsertData.user_id}` : upsertData.id;
          const existing = map.get(key) || {};
          const item = {
            ...existing,
            ...upsertData,
            created_at: existing.created_at || new Date().toISOString(),
            updated_at: new Date().toISOString()
          };
          map.set(key, item);
          return { data: item, error: null };
        }

        let rows = [...map.values()];
        for (const f of filters) rows = rows.filter(f);

        if (operation === 'delete') {
          for (const row of rows) {
            const key = table === 'document_permissions' ? `${row.document_id}:${row.user_id}` : row.id;
            map.delete(key);
          }
          return { data: rows, error: null };
        }

        if (operation === 'update') {
          const updatedRows = [];
          for (const row of rows) {
            const key = table === 'document_permissions' ? `${row.document_id}:${row.user_id}` : row.id;
            const updated = { ...row, ...updateData, updated_at: new Date().toISOString() };
            map.set(key, updated);
            updatedRows.push(updated);
          }
          return { data: updatedRows.length === 1 ? updatedRows[0] : updatedRows, error: null };
        }

        // select
        if (orderCol) {
          rows.sort((a, b) => (a[orderCol] > b[orderCol] ? (orderAsc ? 1 : -1) : (orderAsc ? -1 : 1)));
        }
        if (limitCount) rows = rows.slice(0, limitCount);
        return { data: rows, error: null };
      },
      async maybeSingle() {
        const res = await builder.execute();
        if (res.error) return res;
        const rows = Array.isArray(res.data) ? res.data : [res.data];
        return { data: rows[0] || null, error: null };
      },
      async single() {
        const res = await builder.execute();
        if (res.error) return res;
        const rows = Array.isArray(res.data) ? res.data : [res.data];
        if (!rows.length || !rows[0]) return { data: null, error: new Error('Row not found') };
        return { data: rows[0], error: null };
      },
      then(onFulfilled, onRejected) {
        return builder.execute().then(onFulfilled, onRejected);
      }
    };

    return builder;
  }

  const admin = {
    auth: {
      getUser: async (token) => {
        const profile = [...profiles.values()].find(p => p.token === token);
        if (!profile) return { data: { user: null }, error: new Error('Invalid token') };
        return { data: { user: { id: profile.id } }, error: null };
      },
      admin: {
        signOut: async () => ({})
      }
    },
    from: (table) => createQueryBuilder(table),
    storage: {
      from: (_bucket) => ({
        upload: async (path, buffer, options) => {
          storageObjects.set(path, { path, buffer, contentType: options?.contentType });
          return { data: { path }, error: null };
        },
        download: async (path) => {
          const item = storageObjects.get(path);
          if (!item) return { data: null, error: new Error('Storage file not found') };
          return {
            data: {
              arrayBuffer: async () => {
                const buf = item.buffer;
                return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
              }
            },
            error: null
          };
        },
        remove: async (paths) => {
          for (const p of paths) storageObjects.delete(p);
          return { data: paths, error: null };
        }
      })
    }
  };

  const createPublicClient = () => ({
    auth: {
      signInWithPassword: async ({ email, password }) => {
        const profile = [...profiles.values()].find(p => p.email === email && p.password === password);
        if (!profile) return { data: { user: null, session: null }, error: new Error('Invalid login') };
        return {
          data: {
            user: { id: profile.id, email: profile.email },
            session: { access_token: profile.token, refresh_token: `ref-${profile.token}`, expires_in: 3600 }
          },
          error: null
        };
      },
      signOut: async () => ({ error: null }),
      refreshSession: async ({ refresh_token }) => {
        const profile = [...profiles.values()].find(p => `ref-${p.token}` === refresh_token);
        if (!profile) return { data: { session: null }, error: new Error('Invalid refresh token') };
        return {
          data: {
            session: { access_token: profile.token, refresh_token, expires_in: 3600 }
          },
          error: null
        };
      }
    }
  });

  return { admin, createPublicClient, tables: { profiles, documents, permissions, auditEvents, storageObjects } };
}
