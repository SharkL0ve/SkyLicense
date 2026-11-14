//! Java Agent detection through JVM arguments, known classes, JDWP, and
//! runtime module observations.

use jni::JNIEnv;
use jni::objects::{JString, JValue};
use std::ops::DerefMut;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

/// 是否已检测到 agent（全局标记，一旦为 true 不可恢复）
static AGENT_DETECTED: OnceLock<AtomicBool> = OnceLock::new();

/// Agent 检测结果
pub struct AgentDetectionResult {
    pub jvm_args_agents: bool,
    pub instrumentation_loaded: bool,
    pub known_agent_classes: Vec<&'static str>,
    pub jdwp_active: bool,
    pub attach_api_loaded: bool,
}

impl AgentDetectionResult {
    pub fn is_compromised(&self) -> bool {
        self.jvm_args_agents
            || self.instrumentation_loaded
            || !self.known_agent_classes.is_empty()
            || self.jdwp_active
            || self.attach_api_loaded
    }
}

// ============================================================
// 检测 JVM 启动参数中的 agent 标志
// ============================================================

/// 通过 ManagementFactory.getRuntimeMXBean().getInputArguments() 获取 JVM 参数
/// 检测 -javaagent: / -agentlib: / -agentpath: / -Xrunjdwp
fn jvm_input_arguments(env: &JNIEnv) -> Option<Vec<String>> {
    let mut env = unsafe { env.unsafe_clone() };

    let mgmt_class = match env.find_class("java/lang/management/ManagementFactory") {
        Ok(c) => c,
        Err(_) => return None,
    };

    // getRuntimeMXBean() -> RuntimeMXBean
    let mxbean = match env.call_static_method(
        &mgmt_class,
        "getRuntimeMXBean",
        "()Ljava/lang/management/RuntimeMXBean;",
        &[],
    ) {
        Ok(v) => match v.l() {
            Ok(obj) => obj,
            Err(_) => return None,
        },
        Err(_) => return None,
    };

    // getInputArguments() -> List<String>
    let args_list = match env.call_method(&mxbean, "getInputArguments", "()Ljava/util/List;", &[]) {
        Ok(v) => match v.l() {
            Ok(obj) => obj,
            Err(_) => return None,
        },
        Err(_) => return None,
    };

    // List.size()
    let size = match env.call_method(&args_list, "size", "()I", &[]) {
        Ok(v) => match v.i() {
            Ok(i) => i,
            Err(_) => return None,
        },
        Err(_) => return None,
    };

    if !(0..=4096).contains(&size) {
        return None;
    }

    let mut arguments = Vec::with_capacity(size as usize);
    for i in 0..size {
        let arg_obj = match env.call_method(
            &args_list,
            "get",
            "(I)Ljava/lang/Object;",
            &[JValue::from(i)],
        ) {
            Ok(v) => match v.l() {
                Ok(obj) => obj,
                Err(_) => continue,
            },
            Err(_) => continue,
        };

        if arg_obj.is_null() {
            continue;
        }

        let arg_str: String = match env.get_string(&JString::from(arg_obj)) {
            Ok(s) => s.into(),
            Err(_) => continue,
        };

        arguments.push(arg_str);
    }

    Some(arguments)
}

fn contains_agent_argument(arguments: &[String]) -> bool {
    arguments.iter().any(|argument| {
        let lower = argument.to_ascii_lowercase();
        lower.starts_with("-javaagent:")
            || lower.starts_with("-agentlib:")
            || lower.starts_with("-agentpath:")
            || lower.contains("-xrunjdwp")
            || lower.contains("jdwp=transport")
    })
}

fn check_jvm_args(env: &JNIEnv) -> bool {
    jvm_input_arguments(env)
        .as_deref()
        .is_some_and(contains_agent_argument)
}

// ============================================================
// 检测已加载的 agent 相关类
// ============================================================

/// 已知的 agent / 字节码操作框架类名
/// 注意：只包含明确表示 agent 正在运行的类，不包含 JDK 自带类或常见库
const AGENT_CLASSES: &[&str] = &[
    // ByteBuddy Agent (not the library itself, but the agent entry point)
    "net/bytebuddy/agent/ByteBuddyAgent",
    // Arthas (runtime attach tool)
    "com/taobao/arthas/core/server/ArthasBootstrap",
    "com/alibaba/arthas/tunnel/client/TunnelClient",
    // JRebel
    "com/zeroturnaround/javarebel/Startup",
    "org/zeroturnaround/javarebel/RebelAgent",
    // Spring-loaded
    "org/springsource/loaded/agent/SpringLoadedAgent",
    // JProfiler agent (not the API)
    "com/jprofiler/agent/Controller",
    // YourKit agent
    "com/yourkit/agent/Controller",
];

/// 逐个尝试 findClass，检测哪些 agent 类已被加载
fn detect_loaded_agent_classes(env: &JNIEnv) -> Vec<&'static str> {
    let mut env = unsafe { env.unsafe_clone() };
    let mut found = Vec::new();

    for &class_name in AGENT_CLASSES {
        if env.find_class(class_name).is_ok() {
            found.push(class_name);
        }
        // findClass 失败会设置异常，需要清除
        let _ = env.exception_clear();
    }

    found
}

// ============================================================
// 检测 Instrumentation 是否已注册
// ============================================================

/// 检查是否有 agent 真正注册了 ClassFileTransformer。
/// 仅检查类是否存在不够——JDK 自带这个类。
/// 改为检查 JVM 启动参数中是否有 -javaagent 标志（更可靠）。
fn check_instrumentation_loaded(env: &JNIEnv) -> bool {
    // InstrumentationImpl 在 JDK 中始终存在，不能作为判断依据。
    // 真正的判断是：是否有 -javaagent 参数（已在 check_jvm_args 中覆盖）。
    // 这里只做补充检测：检查是否有 premain/agentmain 被调用的痕迹。
    let mut env = unsafe { env.unsafe_clone() };

    // 检查是否有 java.lang.instrument.ClassFileTransformer 的实现类被加载
    // 这比检查 InstrumentationImpl 更精确
    let has_transformer = env
        .find_class("java/lang/instrument/ClassFileTransformer")
        .is_ok();
    let _ = env.exception_clear();

    if !has_transformer {
        return false;
    }

    // ClassFileTransformer 接口在 JDK 中始终存在，但如果没有 agent 注册，
    // 不会有实际的 transformer 实例。我们无法通过 findClass 判断是否有实例。
    // 所以这里返回 false，依赖 check_jvm_args 来检测 -javaagent。
    false
}

// ============================================================
// 检测 JDWP 调试端口
// ============================================================

/// 通过系统属性判断是否开启了远程调试（JDWP）
/// 不依赖类存在性（JDK 自带 com.sun.jdi 模块）
fn check_jdwp_active(env: &JNIEnv) -> bool {
    let mut env = unsafe { env.unsafe_clone() };

    // 检查系统属性 sun.jdwp.listenerAddress（只有 JDWP 真正启动时才会设置）
    if let Some(val) = get_system_property(&mut env, "sun.jdwp.listenerAddress")
        && !val.is_empty()
    {
        return true;
    }

    false
}

// ============================================================
// 检测 Attach API
// ============================================================

/// 检测 Attach API 是否被主动使用（不是仅存在）
/// JDK 9+ 的 jdk.attach 模块默认可见，类存在不代表被使用
fn check_attach_api_loaded(_env: &JNIEnv) -> bool {
    // com.sun.tools.attach.VirtualMachine 在 JDK 9+ 始终可见，
    // 不能作为判断依据。真正的 attach 检测由 anti_attach 模块负责
    // （文件监控 + 线程检测）。这里不做误报检测。
    false
}

// ============================================================
// 禁用未来的 agent 加载
// ============================================================

/// 设置系统属性阻止后续 attach
pub fn disable_future_agent_loading(env: &JNIEnv) {
    let mut env = unsafe { env.unsafe_clone() };

    let properties = [
        ("jdk.attach.allowAttachSelf", "false"),
        ("jdk.attach.disabled", "true"),
    ];

    for (key, value) in &properties {
        let _ = set_system_property(&mut env, key, value);
    }
}

// ============================================================
// 辅助函数
// ============================================================

fn get_system_property(env: &mut JNIEnv, key: &str) -> Option<String> {
    let system_class = env.find_class("java/lang/System").ok()?;
    let key_str = env.new_string(key).ok()?;

    let result = env
        .call_static_method(
            &system_class,
            "getProperty",
            "(Ljava/lang/String;)Ljava/lang/String;",
            &[JValue::from(&key_str)],
        )
        .ok()?
        .l()
        .ok()?;

    if result.is_null() {
        return None;
    }

    let s: String = env.get_string(&JString::from(result)).ok()?.into();
    Some(s)
}

fn set_system_property(env: &mut JNIEnv, key: &str, value: &str) -> Option<()> {
    let system_class = env.find_class("java/lang/System").ok()?;
    let key_str = env.new_string(key).ok()?;
    let val_str = env.new_string(value).ok()?;

    env.call_static_method(
        &system_class,
        "setProperty",
        "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
        &[JValue::from(&key_str), JValue::from(&val_str)],
    )
    .ok()?;

    Some(())
}

fn parse_jvm_feature_version(version: &str) -> Option<u32> {
    let normalized = version.strip_prefix("1.").unwrap_or(version);
    normalized.split('.').next()?.parse().ok()
}

fn jvm_hardening_gaps(arguments: &[String], feature_version: Option<u32>) -> Vec<&'static str> {
    let mut gaps = Vec::new();
    if !arguments
        .iter()
        .any(|argument| argument.eq_ignore_ascii_case("-XX:+DisableAttachMechanism"))
    {
        gaps.push("missing -XX:+DisableAttachMechanism");
    }
    if feature_version.is_some_and(|version| version >= 9)
        && !arguments
            .iter()
            .any(|argument| argument.eq_ignore_ascii_case("-XX:-EnableDynamicAgentLoading"))
    {
        gaps.push("missing -XX:-EnableDynamicAgentLoading");
    }
    gaps
}

fn validate_jvm_hardening(env: &JNIEnv) -> Result<(), String> {
    let policy = crate::security::policy();
    let feature_version = {
        let mut env = unsafe { env.unsafe_clone() };
        get_system_property(&mut env, "java.specification.version")
            .as_deref()
            .and_then(parse_jvm_feature_version)
    };
    let Some(arguments) = jvm_input_arguments(env) else {
        crate::security::submit(crate::security::SecurityEvidence::new(
            crate::security::EvidenceKind::RuntimeFailure,
            crate::security::EvidenceConfidence::Medium,
            "attach.jvm_arguments",
            "unable to verify the JVM attach-hardening arguments",
        ));
        return if policy.require_jvm_attach_hardening {
            Err("E024".to_string())
        } else {
            Ok(())
        };
    };

    let gaps = jvm_hardening_gaps(&arguments, feature_version);
    for gap in &gaps {
        crate::security::submit(crate::security::SecurityEvidence::new(
            crate::security::EvidenceKind::AttachAttempt,
            match policy.profile {
                crate::security::SecurityProfile::Compatible => {
                    crate::security::EvidenceConfidence::Low
                }
                crate::security::SecurityProfile::Balanced
                | crate::security::SecurityProfile::Strict => {
                    crate::security::EvidenceConfidence::Medium
                }
            },
            "attach.jvm_startup_policy",
            *gap,
        ));
    }

    if policy.require_jvm_attach_hardening && !gaps.is_empty() {
        Err("E024".to_string())
    } else {
        Ok(())
    }
}

// ============================================================
// 公开 API
// ============================================================

/// 执行一次全面的 agent 检测，返回检测结果
pub fn detect_agents(env: &JNIEnv) -> AgentDetectionResult {
    AgentDetectionResult {
        jvm_args_agents: check_jvm_args(env),
        instrumentation_loaded: check_instrumentation_loaded(env),
        known_agent_classes: detect_loaded_agent_classes(env),
        jdwp_active: check_jdwp_active(env),
        attach_api_loaded: check_attach_api_loaded(env),
    }
}

/// 初始检测：认证时调用一次。如果检测到 agent 立即返回错误。
pub fn initial_agent_check(env: &JNIEnv) -> Result<(), String> {
    let result = detect_agents(env);

    // 调试输出：显示具体哪项检测命中
    if result.jvm_args_agents {
        crate::debug_log!("[SkyLicense] Agent detected: JVM args contain agent flags");
    }
    if result.instrumentation_loaded {
        crate::debug_log!("[SkyLicense] Agent detected: Instrumentation class loaded");
    }
    if !result.known_agent_classes.is_empty() {
        crate::debug_log!(
            "[SkyLicense] Agent detected: known classes found: {:?}",
            result.known_agent_classes
        );
    }
    if result.jdwp_active {
        crate::debug_log!("[SkyLicense] Agent detected: JDWP active");
    }
    if result.attach_api_loaded {
        crate::debug_log!("[SkyLicense] Agent detected: Attach API loaded");
    }

    if result.is_compromised() {
        AGENT_DETECTED.get_or_init(|| AtomicBool::new(true));
        crate::security::submit(crate::security::SecurityEvidence::new(
            crate::security::EvidenceKind::JavaAgent,
            crate::security::EvidenceConfidence::High,
            "agent.initial",
            "Java/JVMTI agent indicators were present during protection initialization",
        ));
        if crate::security::state().is_terminal() {
            return Err("E020".to_string());
        }
    }

    validate_jvm_hardening(env)?;

    // 禁用后续 attach
    disable_future_agent_loading(env);

    // 标记为安全
    AGENT_DETECTED.get_or_init(|| AtomicBool::new(false));
    Ok(())
}

/// 启动后台 agent 监控线程。
/// 定期通过 JNI 重新检测是否有新 agent 被加载。
/// 需要传入 JavaVM 指针以便在新线程中 attach。
pub fn start_agent_monitor(vm: jni::JavaVM) -> Result<(), String> {
    crate::security::spawn_ready_monitor(
        "sky-agent-monitor",
        std::time::Duration::from_secs(5),
        move |stop, ready| {
            let mut guard = match vm.attach_current_thread() {
                Ok(guard) => guard,
                Err(error) => {
                    let _ = ready.send(Err(format!(
                        "failed to attach agent monitor to JVM: {error}"
                    )));
                    return;
                }
            };

            let initial = detect_agents(guard.deref_mut());
            if initial.is_compromised() {
                crate::security::submit(crate::security::SecurityEvidence::new(
                    crate::security::EvidenceKind::JavaAgent,
                    crate::security::EvidenceConfidence::High,
                    "agent.monitor_initial",
                    "agent indicators appeared before the runtime monitor became ready",
                ));
                if crate::security::state().is_terminal() {
                    let _ = ready.send(Err(
                        "agent indicators detected during monitor startup".to_string()
                    ));
                    return;
                }
            }
            if ready.send(Ok(())).is_err() {
                return;
            }

            while !stop.load(Ordering::Acquire) {
                if crate::security::wait_for_stop(&stop, std::time::Duration::from_secs(2)) {
                    break;
                }

                let env: &mut JNIEnv = guard.deref_mut();

                // 重新检测
                let result = detect_agents(env);
                if result.is_compromised() {
                    // Agent 被运行时注入 — 必须退出，因为 agent 可以读取 JVM 内部类信息
                    if let Some(flag) = AGENT_DETECTED.get() {
                        flag.store(true, Ordering::Release);
                    }
                    let evidence = crate::security::SecurityEvidence::new(
                        crate::security::EvidenceKind::JavaAgent,
                        crate::security::EvidenceConfidence::High,
                        "agent.runtime",
                        "runtime Java/JVMTI agent indicators detected",
                    );
                    crate::security::submit(evidence);
                    break;
                }
            }
        },
    )
}

/// 快速检查：agent 是否已被检测到（无 JNI 开销，仅读原子变量）
#[inline]
pub fn is_agent_detected() -> bool {
    AGENT_DETECTED
        .get()
        .map(|b| b.load(Ordering::Relaxed))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn parses_legacy_and_modern_jvm_versions() {
        assert_eq!(parse_jvm_feature_version("1.8"), Some(8));
        assert_eq!(parse_jvm_feature_version("17"), Some(17));
        assert_eq!(parse_jvm_feature_version("21.0.2"), Some(21));
        assert_eq!(parse_jvm_feature_version("invalid"), None);
    }

    #[test]
    fn hardening_policy_is_version_aware() {
        let hardened = arguments(&[
            "-XX:+DisableAttachMechanism",
            "-XX:-EnableDynamicAgentLoading",
        ]);
        assert!(jvm_hardening_gaps(&hardened, Some(21)).is_empty());

        let jdk8 = arguments(&["-XX:+DisableAttachMechanism"]);
        assert!(jvm_hardening_gaps(&jdk8, Some(8)).is_empty());

        let gaps = jvm_hardening_gaps(&[], Some(21));
        assert_eq!(gaps.len(), 2);
    }

    #[test]
    fn agent_argument_matching_avoids_unrelated_options() {
        assert!(contains_agent_argument(&arguments(&[
            "-agentlib:jdwp=transport=dt_socket"
        ])));
        assert!(!contains_agent_argument(&arguments(&[
            "-Dapplication.agentName=ordinary"
        ])));
    }
}
