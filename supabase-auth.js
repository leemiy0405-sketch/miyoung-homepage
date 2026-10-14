(function (root) {
  'use strict';
  var config = root.MIYOUNG_SUPABASE_CONFIG || {};
  var client = null, listener = null, revision = 0, activeRefresh = null;
  var state = { ready: false, user: null, admin: false, error: null };

  function notify() { if (listener) listener(Object.assign({}, state)); }
  function message(error) {
    var code = error && error.code;
    if (code === 'invalid_credentials') return '이메일 또는 비밀번호가 맞지 않습니다.';
    if (code === 'email_not_confirmed') return '가입한 이메일의 인증 링크를 먼저 눌러 주세요.';
    if (code === 'user_already_exists') return '이미 가입된 이메일입니다. 로그인해 주세요.';
    if (code === 'over_email_send_rate_limit' || code === 'over_request_rate_limit') return '요청이 많습니다. 잠시 후 다시 시도해 주세요.';
    if (code === 'signup_disabled') return '현재 회원가입이 비활성화되어 있습니다.';
    if (code === 'email_address_not_authorized') return '현재 이 이메일로 인증 메일을 보낼 수 없습니다. 관리자에게 이메일 발송 설정을 요청해 주세요.';
    if (code === 'weak_password') return '더 강한 비밀번호를 사용해 주세요.';
    return '요청을 처리하지 못했습니다. 연결 상태와 Supabase 설정을 확인해 주세요.';
  }
  function requireClient() {
    if (!client) throw new Error('로그인 서비스 연결을 준비 중입니다. 잠시 후 다시 이용해 주세요.');
  }
  function refresh() {
    if (activeRefresh) return activeRefresh;
    var promise = refreshState().finally(function () { if (activeRefresh === promise) activeRefresh = null; });
    activeRefresh = promise;
    return promise;
  }
  async function refreshState() {
    if (!client) return;
    var current = ++revision;
    state.admin = false;
    state.ready = false;
    notify();
    try {
      var sessionResult = await client.auth.getSession();
      if (sessionResult.error) throw sessionResult.error;
      var session = sessionResult.data.session;
      if (!session) {
        if (current !== revision) return;
        state = { ready: true, user: null, admin: false, error: null };
        notify();
        return;
      }
      var userResult = await client.auth.getUser();
      if (userResult.error) throw userResult.error;
      var roleResult = await client.rpc('is_site_admin');
      if (current !== revision) return;
      state = {
        ready: true,
        user: userResult.data.user,
        admin: !roleResult.error && roleResult.data === true,
        error: roleResult.error ? '관리자 권한 설정을 확인하지 못했습니다.' : null
      };
    } catch (error) {
      if (current !== revision) return;
      state = { ready: true, user: null, admin: false, error: message(error) };
    }
    notify();
  }
  async function initialize(onChange) {
    listener = onChange;
    // A legacy anon JWT is accepted only if its embedded role is actually anon.
    var key = config.publishableKey || '', safeKey = key.indexOf('sb_publishable_') === 0;
    if (!safeKey && key.indexOf('eyJ') === 0) {
      try { safeKey = JSON.parse(root.atob(key.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))).role === 'anon'; } catch (_) {}
    }
    if (!safeKey || !root.supabase || !/^https:\/\/[^/]+\.supabase\.co$/.test(config.url || '')) {
      state = { ready: true, user: null, admin: false, error: '로그인 서비스 연결을 준비 중입니다.' };
      notify();
      return;
    }
    client = root.supabase.createClient(config.url, key, {
      auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true, flowType: 'implicit', storageKey: 'miyoung_supabase_auth' }
    });
    client.auth.onAuthStateChange(function (event, session) {
      if (event === 'SIGNED_OUT') {
        ++revision;
        activeRefresh = null;
        state = { ready: true, user: null, admin: false, error: null };
        notify();
      } else {
        if (state.user && (!session || !session.user || session.user.id !== state.user.id)) {
          ++revision;
          activeRefresh = null;
          state = { ready: false, user: null, admin: false, error: null };
          notify();
        }
        // Run outside the Auth callback lock before making another SDK call.
        root.setTimeout(refresh, 0);
      }
    });
    await refresh();
  }
  async function signIn(email, password) {
    requireClient();
    var result = await client.auth.signInWithPassword({ email: email, password: password });
    if (result.error) throw new Error(message(result.error));
    await refresh();
    return Object.assign({}, state);
  }
  async function signUp(name, email, password) {
    requireClient();
    var result = await client.auth.signUp({
      email: email, password: password,
      options: { data: { name: name }, emailRedirectTo: config.siteUrl }
    });
    if (result.error) throw new Error(message(result.error));
    if (result.data.session) await refresh();
    return { confirmationRequired: !result.data.session };
  }
  async function signOut() {
    requireClient();
    var result = await client.auth.signOut();
    if (result.error) throw new Error(message(result.error));
    ++revision;
    state = { ready: true, user: null, admin: false, error: null };
    notify();
  }
  async function listMembers(offset, limit) {
    requireClient();
    if (!state.ready || !state.admin || !state.user) throw new Error('관리자 계정으로 로그인해 주세요.');
    var current = revision, userId = state.user.id;
    var result = await client.rpc('list_site_members', { p_offset: offset, p_limit: limit });
    if (current !== revision || !state.admin || !state.user || state.user.id !== userId) throw new Error('로그인 상태가 변경되었습니다.');
    if (result.error) {
      if (result.error.code === '42501') {
        state.admin = false;
        notify();
        throw new Error('관리자 권한이 없습니다.');
      }
      throw new Error('회원 목록을 불러오지 못했습니다. Supabase 권한 설정을 확인해 주세요.');
    }
    return result.data || [];
  }
  root.MiyoungAuth = Object.freeze({ initialize: initialize, signIn: signIn, signUp: signUp, signOut: signOut, listMembers: listMembers });
})(window);
