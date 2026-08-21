use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::process::Command;
use tokio::sync::Mutex;

use runonmine_core::AppPaths;

const DEDUPE_WINDOW: Duration = Duration::from_mins(5);
const END_SILENCE_MS: u64 = 2_500;
const SPEECH_THRESHOLD_DB: i32 = -43;
const CONFIDENCE_THRESHOLD: f64 = 0.82;
const REPEAT_THRESHOLD: f64 = 0.70;
const SHORT_WORD_THRESHOLD: usize = 6;
const SHORT_TOKEN_THRESHOLD: usize = 8;

#[derive(Clone, Debug, Serialize)]
pub(super) struct VoiceStatus {
    pub(super) available: bool,
    pub(super) components: BTreeMap<&'static str, bool>,
    pub(super) end_silence_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct VoiceNotifyResult {
    pub(super) engine: String,
    pub(super) voice: String,
    pub(super) fallback: bool,
    pub(super) deduplicated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct CaptureInfo {
    #[serde(rename = "durationSeconds", default)]
    pub(super) duration_seconds: f64,
    #[serde(rename = "speechDetected", default)]
    pub(super) speech_detected: bool,
    #[serde(rename = "autoStopped", default)]
    pub(super) auto_stopped: bool,
    #[serde(rename = "voiceProcessing", default)]
    pub(super) voice_processing: bool,
    #[serde(rename = "peakDb", default)]
    pub(super) peak_db: f64,
    #[serde(rename = "sampleRate", default)]
    pub(super) sample_rate: u32,
    #[serde(default)]
    pub(super) channels: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum FallbackState {
    NotRun,
    Checked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum AgreementState {
    NotCompared,
    Agreed,
    Disagreed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RepeatState {
    Accepted,
    Recommended,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum DedupeOutcome {
    Fresh,
    Reused,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct VoiceTranscriptResult {
    pub(super) transcript: String,
    pub(super) confidence: f64,
    pub(super) min_confidence: f64,
    pub(super) lexical_token_count: usize,
    pub(super) word_count: usize,
    pub(super) model: String,
    pub(super) primary_model: String,
    pub(super) fallback: FallbackState,
    pub(super) agreement: AgreementState,
    pub(super) repeat: RepeatState,
    pub(super) primary_transcript: String,
    pub(super) fallback_transcript: String,
    pub(super) primary_confidence: f64,
    pub(super) fallback_confidence: Option<f64>,
    pub(super) transcription_ms: u64,
    pub(super) max_listen_seconds: u64,
    pub(super) capture: CaptureInfo,
    pub(super) attempts: u8,
    pub(super) dedupe: DedupeOutcome,
}

impl VoiceTranscriptResult {
    pub(super) fn needs_repeat(&self) -> bool {
        self.repeat == RepeatState::Recommended
    }

    pub(super) fn deduplicated(&self) -> bool {
        self.dedupe == DedupeOutcome::Reused
    }

    fn mark_reused(&mut self) {
        self.dedupe = DedupeOutcome::Reused;
    }
}

#[derive(Clone, Debug)]
struct TranscriptCandidate {
    transcript: String,
    normalized: String,
    confidence: f64,
    min_confidence: f64,
    lexical_token_count: usize,
    word_count: usize,
    model: String,
    elapsed_ms: u64,
}

#[derive(Clone, Debug)]
struct BestTranscript {
    chosen: TranscriptCandidate,
    primary: TranscriptCandidate,
    fallback: Option<TranscriptCandidate>,
    disagreement: bool,
    needs_repeat: bool,
}

#[derive(Clone, Debug)]
struct VoicePaths {
    recorder: PathBuf,
    whisper_cli: PathBuf,
    primary_model: PathBuf,
    fallback_model: PathBuf,
    vad_model: PathBuf,
    ffmpeg: PathBuf,
    edge_tts: Option<PathBuf>,
    start_sound: PathBuf,
    stop_sound: PathBuf,
}

impl VoicePaths {
    fn discover() -> Result<Self> {
        let app = AppPaths::discover()?;
        let voice = app.data_dir.join("voice");
        let bin = voice.join("bin");
        let models = voice.join("models");
        let home = std::env::var_os("HOME").map(PathBuf::from);
        Ok(Self {
            recorder: bin.join("runonmine-record-audio"),
            whisper_cli: discover_absolute_program(&[
                "/opt/homebrew/bin/whisper-cli",
                "/usr/local/bin/whisper-cli",
            ])
            .unwrap_or_else(|| PathBuf::from("/opt/homebrew/bin/whisper-cli")),
            primary_model: models.join("ggml-large-v3-turbo-q8_0.bin"),
            fallback_model: models.join("ggml-large-v3-q5_0.bin"),
            vad_model: models.join("ggml-silero-v6.2.0.bin"),
            ffmpeg: discover_absolute_program(&[
                "/opt/homebrew/bin/ffmpeg",
                "/usr/local/bin/ffmpeg",
                "/usr/bin/ffmpeg",
            ])
            .unwrap_or_else(|| PathBuf::from("/opt/homebrew/bin/ffmpeg")),
            edge_tts: home
                .map(|path| path.join(".local/bin/edge-tts"))
                .filter(|path| path.is_file()),
            start_sound: PathBuf::from("/System/Library/Sounds/Tink.aiff"),
            stop_sound: PathBuf::from("/System/Library/Sounds/Pop.aiff"),
        })
    }

    fn status(&self) -> VoiceStatus {
        let recorder = self.recorder.is_file();
        let whisper_cli = self.whisper_cli.is_file();
        let primary_model = self.primary_model.is_file();
        let fallback_model = self.fallback_model.is_file();
        let vad_model = self.vad_model.is_file();
        let ffmpeg = self.ffmpeg.is_file();
        let components = BTreeMap::from([
            ("recorder", recorder),
            ("whisper_cli", whisper_cli),
            ("primary_model", primary_model),
            ("fallback_model", fallback_model),
            ("vad_model", vad_model),
            ("ffmpeg", ffmpeg),
            (
                "neural_tts",
                self.edge_tts.as_ref().is_some_and(|path| path.is_file()),
            ),
        ]);
        VoiceStatus {
            available: recorder && whisper_cli && primary_model && vad_model && ffmpeg,
            components,
            end_silence_ms: END_SILENCE_MS,
        }
    }
}

fn discover_absolute_program(candidates: &[&str]) -> Option<PathBuf> {
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_absolute() && path.is_file())
}

#[derive(Clone, Debug)]
struct CachedAsk {
    hash: [u8; 32],
    completed_at: Instant,
    result: VoiceTranscriptResult,
}

#[derive(Clone, Debug)]
struct RecentNotify {
    hash: [u8; 32],
    completed_at: Instant,
}

#[derive(Debug, Default)]
struct DedupeState {
    asks: VecDeque<CachedAsk>,
    notifies: VecDeque<RecentNotify>,
}

impl DedupeState {
    fn prune(&mut self) {
        while self
            .asks
            .front()
            .is_some_and(|item| item.completed_at.elapsed() > DEDUPE_WINDOW)
        {
            self.asks.pop_front();
        }
        while self
            .notifies
            .front()
            .is_some_and(|item| item.completed_at.elapsed() > DEDUPE_WINDOW)
        {
            self.notifies.pop_front();
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct VoiceService {
    paths: VoicePaths,
    operation_gate: Arc<Mutex<()>>,
    dedupe: Arc<Mutex<DedupeState>>,
}

impl VoiceService {
    pub(super) fn discover() -> Result<Self> {
        Ok(Self {
            paths: VoicePaths::discover()?,
            operation_gate: Arc::new(Mutex::new(())),
            dedupe: Arc::new(Mutex::new(DedupeState::default())),
        })
    }

    pub(super) fn status(&self) -> VoiceStatus {
        self.paths.status()
    }

    pub(super) async fn notify(
        &self,
        text: &str,
        voice: &str,
        rate_percent: i32,
    ) -> Result<VoiceNotifyResult> {
        let clean = validate_spoken_text(text)?;
        let selected = normalize_voice(voice)?;
        let rate_percent = rate_percent.clamp(-40, 40);
        let hash = voice_hash("notify", clean, selected, rate_percent, "");
        let _gate = self.operation_gate.lock().await;
        {
            let mut dedupe = self.dedupe.lock().await;
            dedupe.prune();
            if dedupe.notifies.iter().any(|item| item.hash == hash) {
                return Ok(VoiceNotifyResult {
                    engine: "deduplicated".to_owned(),
                    voice: selected.to_owned(),
                    fallback: false,
                    deduplicated: true,
                });
            }
        }
        let mut result = self.speak_inner(clean, selected, rate_percent).await?;
        result.deduplicated = false;
        let mut dedupe = self.dedupe.lock().await;
        dedupe.prune();
        dedupe.notifies.push_back(RecentNotify {
            hash,
            completed_at: Instant::now(),
        });
        Ok(result)
    }

    pub(super) async fn listen(
        &self,
        listen_seconds: u64,
        language: &str,
        context: &str,
    ) -> Result<VoiceTranscriptResult> {
        let _gate = self.operation_gate.lock().await;
        self.listen_inner(listen_seconds, language, context).await
    }

    pub(super) async fn ask(
        &self,
        question: &str,
        listen_seconds: u64,
        voice: &str,
        rate_percent: i32,
        language: &str,
    ) -> Result<VoiceTranscriptResult> {
        let clean = validate_spoken_text(question)?;
        let selected = normalize_voice(voice)?;
        let language = validate_language(language)?;
        let rate_percent = rate_percent.clamp(-40, 40);
        let hash = voice_hash("ask", clean, selected, rate_percent, language);
        let _gate = self.operation_gate.lock().await;
        {
            let mut dedupe = self.dedupe.lock().await;
            dedupe.prune();
            if let Some(cached) = dedupe.asks.iter().find(|item| item.hash == hash) {
                let mut result = cached.result.clone();
                result.mark_reused();
                return Ok(result);
            }
        }

        self.speak_inner(clean, selected, rate_percent).await?;
        let mut first = self.listen_inner(listen_seconds, language, clean).await?;
        first.attempts = 1;
        let result = if first.needs_repeat() {
            self.speak_inner(
                "Cevabını net anlayamadım. Lütfen tekrar söyler misin?",
                selected,
                rate_percent,
            )
            .await?;
            let mut second = self.listen_inner(listen_seconds, language, clean).await?;
            second.attempts = 2;
            if second.transcript.is_empty() {
                first
            } else {
                second
            }
        } else {
            first
        };

        let mut dedupe = self.dedupe.lock().await;
        dedupe.prune();
        dedupe.asks.push_back(CachedAsk {
            hash,
            completed_at: Instant::now(),
            result: result.clone(),
        });
        Ok(result)
    }

    async fn speak_inner(
        &self,
        text: &str,
        voice: &str,
        rate_percent: i32,
    ) -> Result<VoiceNotifyResult> {
        let voice_id = match voice {
            "ahmet" => "tr-TR-AhmetNeural",
            "emel" => "tr-TR-EmelNeural",
            "yelda" => "Yelda",
            _ => bail!("unsupported voice"),
        };
        if voice == "yelda" {
            run_program(
                Path::new("/usr/bin/say"),
                &["-v".into(), voice_id.into(), text.into()],
                Duration::from_mins(3),
            )
            .await?;
            return Ok(VoiceNotifyResult {
                engine: "macOS say".to_owned(),
                voice: voice_id.to_owned(),
                fallback: false,
                deduplicated: false,
            });
        }

        if let Some(edge_tts) = &self.paths.edge_tts {
            let temp = tempfile::tempdir().context("failed to create voice temp directory")?;
            let text_path = temp.path().join("speech.txt");
            let media_path = temp.path().join("speech.mp3");
            tokio::fs::write(&text_path, text).await?;
            let rate = format!("{rate_percent:+}%");
            let edge_result = run_program(
                edge_tts,
                &[
                    "--file".into(),
                    text_path.to_string_lossy().into_owned(),
                    "--voice".into(),
                    voice_id.into(),
                    "--rate".into(),
                    rate,
                    "--write-media".into(),
                    media_path.to_string_lossy().into_owned(),
                ],
                Duration::from_mins(2),
            )
            .await;
            if edge_result.is_ok() {
                run_program(
                    Path::new("/usr/bin/afplay"),
                    &[media_path.to_string_lossy().into_owned()],
                    Duration::from_mins(3),
                )
                .await?;
                return Ok(VoiceNotifyResult {
                    engine: "edge-tts".to_owned(),
                    voice: voice_id.to_owned(),
                    fallback: false,
                    deduplicated: false,
                });
            }
        }

        run_program(
            Path::new("/usr/bin/say"),
            &["-v".into(), "Yelda".into(), text.into()],
            Duration::from_mins(3),
        )
        .await?;
        Ok(VoiceNotifyResult {
            engine: "macOS say".to_owned(),
            voice: "Yelda".to_owned(),
            fallback: true,
            deduplicated: false,
        })
    }

    async fn listen_inner(
        &self,
        listen_seconds: u64,
        language: &str,
        context: &str,
    ) -> Result<VoiceTranscriptResult> {
        if !self.paths.status().available {
            bail!("local voice transcription dependencies are incomplete")
        }
        let language = validate_language(language)?;
        let max_seconds = listen_seconds.clamp(3, 30);
        let temp = tempfile::tempdir().context("failed to create listen temp directory")?;
        let caf_path = temp.path().join("recording.caf");
        let wav_path = temp.path().join("recording.wav");
        let capture = self.record_capture(&caf_path, max_seconds).await?;
        if !capture.speech_detected {
            return Ok(empty_transcript(max_seconds, capture));
        }
        self.prepare_wav(&caf_path, &wav_path, capture.voice_processing)
            .await?;
        let best = self
            .transcribe_best(&wav_path, language, context, temp.path())
            .await?;
        Ok(transcript_result(&best, max_seconds, capture))
    }

    async fn record_capture(&self, caf_path: &Path, max_seconds: u64) -> Result<CaptureInfo> {
        let recorder = run_program_capture(
            &self.paths.recorder,
            &[
                caf_path.to_string_lossy().into_owned(),
                max_seconds.to_string(),
                END_SILENCE_MS.to_string(),
                SPEECH_THRESHOLD_DB.to_string(),
                self.paths.start_sound.to_string_lossy().into_owned(),
            ],
            Duration::from_secs(max_seconds + 10),
        )
        .await?;
        let _ = run_program(
            Path::new("/usr/bin/afplay"),
            &[self.paths.stop_sound.to_string_lossy().into_owned()],
            Duration::from_secs(15),
        )
        .await;
        recorder
            .stdout
            .lines()
            .rev()
            .find_map(|line| serde_json::from_str(line).ok())
            .context("recorder did not return capture metadata")
    }

    async fn prepare_wav(
        &self,
        caf_path: &Path,
        wav_path: &Path,
        voice_processing: bool,
    ) -> Result<()> {
        let filter = if voice_processing {
            "highpass=f=70,lowpass=f=7800"
        } else {
            "highpass=f=70,lowpass=f=7800,afftdn=nr=6:nf=-52:tn=1"
        };
        run_program(
            &self.paths.ffmpeg,
            &[
                "-hide_banner".into(),
                "-loglevel".into(),
                "error".into(),
                "-y".into(),
                "-i".into(),
                caf_path.to_string_lossy().into_owned(),
                "-af".into(),
                filter.into(),
                "-ar".into(),
                "16000".into(),
                "-ac".into(),
                "1".into(),
                "-c:a".into(),
                "pcm_s16le".into(),
                wav_path.to_string_lossy().into_owned(),
            ],
            Duration::from_mins(1),
        )
        .await
    }

    async fn transcribe_best(
        &self,
        wav_path: &Path,
        language: &str,
        context: &str,
        dir: &Path,
    ) -> Result<BestTranscript> {
        let primary = self
            .transcribe_model(
                wav_path,
                &self.paths.primary_model,
                "large-v3-turbo-q8_0",
                language,
                context,
                dir,
                "primary",
            )
            .await?;
        let should_fallback = primary.transcript.is_empty()
            || primary.confidence < CONFIDENCE_THRESHOLD
            || primary.lexical_token_count <= SHORT_TOKEN_THRESHOLD
            || primary.word_count <= SHORT_WORD_THRESHOLD;
        let fallback = if should_fallback && self.paths.fallback_model.is_file() {
            Some(
                self.transcribe_model(
                    wav_path,
                    &self.paths.fallback_model,
                    "large-v3-q5_0",
                    language,
                    context,
                    dir,
                    "fallback",
                )
                .await?,
            )
        } else {
            None
        };
        let disagreement = fallback.as_ref().is_some_and(|item| {
            !primary.normalized.is_empty()
                && !item.normalized.is_empty()
                && primary.normalized != item.normalized
        });
        let chosen = choose_candidate(&primary, fallback.as_ref());
        let short_answer = chosen.word_count <= SHORT_WORD_THRESHOLD;
        let needs_repeat = chosen.transcript.is_empty()
            || chosen.confidence < REPEAT_THRESHOLD
            || (fallback.is_some() && disagreement && short_answer);
        Ok(BestTranscript {
            chosen,
            primary,
            fallback,
            disagreement,
            needs_repeat,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn transcribe_model(
        &self,
        wav_path: &Path,
        model_path: &Path,
        model_name: &str,
        language: &str,
        context: &str,
        dir: &Path,
        suffix: &str,
    ) -> Result<TranscriptCandidate> {
        let output_prefix = dir.join(format!("whisper-{suffix}"));
        let prompt = build_prompt(language, context);
        let mut args = vec![
            "-m".into(),
            model_path.to_string_lossy().into_owned(),
            "-l".into(),
            language.into(),
            "-nt".into(),
            "-np".into(),
            "-sns".into(),
            "-ojf".into(),
            "-of".into(),
            output_prefix.to_string_lossy().into_owned(),
            "--vad".into(),
            "-vm".into(),
            self.paths.vad_model.to_string_lossy().into_owned(),
            "-vt".into(),
            "0.5".into(),
            "-vspd".into(),
            "200".into(),
            "-vsd".into(),
            "700".into(),
            "-vp".into(),
            "200".into(),
            "-vo".into(),
            "0.1".into(),
        ];
        if !prompt.is_empty() {
            args.push("--prompt".into());
            args.push(prompt);
        }
        args.push("-f".into());
        args.push(wav_path.to_string_lossy().into_owned());
        let started = Instant::now();
        run_program(&self.paths.whisper_cli, &args, Duration::from_mins(3)).await?;
        let json_path = output_prefix.with_extension("json");
        let data: Value = serde_json::from_slice(&tokio::fs::read(json_path).await?)?;
        let mut candidate = score_whisper_json(&data);
        model_name.clone_into(&mut candidate.model);
        candidate.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        Ok(candidate)
    }
}

fn validate_spoken_text(text: &str) -> Result<&str> {
    let clean = text.trim();
    if clean.is_empty() {
        bail!("voice text is empty")
    }
    if clean.chars().count() > 4_000 {
        bail!("voice text exceeds 4000 characters")
    }
    Ok(clean)
}

fn validate_language(language: &str) -> Result<&str> {
    let language = language.trim();
    if !(2..=16).contains(&language.len())
        || !language
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        bail!("invalid voice language")
    }
    Ok(language)
}

fn normalize_voice(voice: &str) -> Result<&str> {
    match voice.trim().to_ascii_lowercase().as_str() {
        "ahmet" => Ok("ahmet"),
        "emel" => Ok("emel"),
        "yelda" => Ok("yelda"),
        _ => bail!("voice must be ahmet, emel, or yelda"),
    }
}

fn voice_hash(kind: &str, text: &str, voice: &str, rate: i32, language: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for value in [kind, text, voice, language] {
        hasher.update(value.as_bytes());
        hasher.update([0]);
    }
    hasher.update(rate.to_le_bytes());
    hasher.finalize().into()
}

fn build_prompt(language: &str, context: &str) -> String {
    let context = context.split_whitespace().collect::<Vec<_>>().join(" ");
    let context = context.chars().take(500).collect::<String>();
    if language.to_ascii_lowercase().starts_with("tr") {
        let base = "Türkçe doğal bir sesli konuşma. Kısa cevaplar, özel isimler ve teknik terimler olabilir. Konuşmayı aynen yazıya dök.";
        if context.is_empty() {
            base.to_owned()
        } else {
            format!("{base} Önceki soru: {context}")
        }
    } else {
        context
    }
}

fn normalize_transcript(text: &str) -> String {
    text.to_lowercase()
        .chars()
        .map(|character| {
            if character.is_alphanumeric() {
                character
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn score_whisper_json(data: &Value) -> TranscriptCandidate {
    let segments = data
        .get("transcription")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let transcript = segments
        .iter()
        .filter_map(|segment| segment.get("text").and_then(Value::as_str))
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let mut probabilities = Vec::new();
    for segment in &segments {
        let Some(tokens) = segment.get("tokens").and_then(Value::as_array) else {
            continue;
        };
        for token in tokens {
            let text = token
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let probability = token.get("p").and_then(Value::as_f64).unwrap_or_default();
            if text.chars().any(char::is_alphanumeric) && (0.0..=1.0).contains(&probability) {
                probabilities.push(probability);
            }
        }
    }
    probabilities.sort_by(f64::total_cmp);
    let (confidence, min_confidence) = if probabilities.is_empty() {
        (0.0, 0.0)
    } else {
        let count = u32::try_from(probabilities.len()).unwrap_or(u32::MAX);
        let average = probabilities.iter().sum::<f64>() / f64::from(count);
        let q25 = probabilities[(probabilities.len() - 1) / 4];
        (
            (average * 0.75 + q25 * 0.25).clamp(0.0, 1.0),
            probabilities[0],
        )
    };
    let normalized = normalize_transcript(&transcript);
    let word_count = normalized.split_whitespace().count();
    TranscriptCandidate {
        transcript,
        normalized,
        confidence,
        min_confidence,
        lexical_token_count: probabilities.len(),
        word_count,
        model: String::new(),
        elapsed_ms: 0,
    }
}

fn choose_candidate(
    primary: &TranscriptCandidate,
    fallback: Option<&TranscriptCandidate>,
) -> TranscriptCandidate {
    let Some(fallback) = fallback else {
        return primary.clone();
    };
    let short_answer = primary.word_count.min(fallback.word_count) <= SHORT_WORD_THRESHOLD;
    if primary.transcript.is_empty() && !fallback.transcript.is_empty() {
        return fallback.clone();
    }
    if fallback.transcript.is_empty() {
        return primary.clone();
    }
    if short_answer && fallback.confidence + 0.12 >= primary.confidence {
        return fallback.clone();
    }
    if fallback.confidence > primary.confidence + 0.03 {
        return fallback.clone();
    }
    primary.clone()
}

fn transcript_result(
    best: &BestTranscript,
    max_listen_seconds: u64,
    capture: CaptureInfo,
) -> VoiceTranscriptResult {
    VoiceTranscriptResult {
        transcript: best.chosen.transcript.clone(),
        confidence: best.chosen.confidence,
        min_confidence: best.chosen.min_confidence,
        lexical_token_count: best.chosen.lexical_token_count,
        word_count: best.chosen.word_count,
        model: best.chosen.model.clone(),
        primary_model: best.primary.model.clone(),
        fallback: if best.fallback.is_some() {
            FallbackState::Checked
        } else {
            FallbackState::NotRun
        },
        agreement: match (&best.fallback, best.disagreement) {
            (None, _) => AgreementState::NotCompared,
            (Some(_), true) => AgreementState::Disagreed,
            (Some(_), false) => AgreementState::Agreed,
        },
        repeat: if best.needs_repeat {
            RepeatState::Recommended
        } else {
            RepeatState::Accepted
        },
        primary_transcript: best.primary.transcript.clone(),
        fallback_transcript: best
            .fallback
            .as_ref()
            .map_or_else(String::new, |item| item.transcript.clone()),
        primary_confidence: best.primary.confidence,
        fallback_confidence: best.fallback.as_ref().map(|item| item.confidence),
        transcription_ms: best.chosen.elapsed_ms,
        max_listen_seconds,
        capture,
        attempts: 1,
        dedupe: DedupeOutcome::Fresh,
    }
}

fn empty_transcript(max_listen_seconds: u64, capture: CaptureInfo) -> VoiceTranscriptResult {
    VoiceTranscriptResult {
        transcript: String::new(),
        confidence: 0.0,
        min_confidence: 0.0,
        lexical_token_count: 0,
        word_count: 0,
        model: "none".to_owned(),
        primary_model: "none".to_owned(),
        fallback: FallbackState::NotRun,
        agreement: AgreementState::NotCompared,
        repeat: RepeatState::Recommended,
        primary_transcript: String::new(),
        fallback_transcript: String::new(),
        primary_confidence: 0.0,
        fallback_confidence: None,
        transcription_ms: 0,
        max_listen_seconds,
        capture,
        attempts: 1,
        dedupe: DedupeOutcome::Fresh,
    }
}

#[derive(Debug)]
struct ProgramOutput {
    stdout: String,
}

async fn run_program(program: &Path, args: &[String], timeout: Duration) -> Result<()> {
    let output = run_program_capture(program, args, timeout).await?;
    if output.stdout.len() > 1_000_000 {
        bail!("voice helper returned excessive output")
    }
    Ok(())
}

async fn run_program_capture(
    program: &Path,
    args: &[String],
    timeout: Duration,
) -> Result<ProgramOutput> {
    if !program.is_absolute() || !program.is_file() {
        bail!("voice helper is unavailable: {}", program.display())
    }
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env(
            "PATH",
            "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        )
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C.UTF-8");
    for name in ["HOME", "TMPDIR"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let child = command
        .spawn()
        .with_context(|| format!("failed to start voice helper {}", program.display()))?;
    let output = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .context("voice helper timed out")??;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "voice helper {} failed: {}",
            program.display(),
            stderr.trim().chars().take(500).collect::<String>()
        )
    }
    Ok(ProgramOutput {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_answer_prefers_accuracy_fallback_when_close() {
        let primary = TranscriptCandidate {
            transcript: "Görüm".into(),
            normalized: "görüm".into(),
            confidence: 0.90,
            min_confidence: 0.8,
            lexical_token_count: 2,
            word_count: 1,
            model: "turbo".into(),
            elapsed_ms: 1,
        };
        let fallback = TranscriptCandidate {
            transcript: "Evet seni duyuyorum".into(),
            normalized: "evet seni duyuyorum".into(),
            confidence: 0.82,
            min_confidence: 0.7,
            lexical_token_count: 4,
            word_count: 3,
            model: "large".into(),
            elapsed_ms: 2,
        };
        assert_eq!(choose_candidate(&primary, Some(&fallback)).model, "large");
    }

    #[test]
    fn voice_hash_changes_with_interaction_kind() {
        assert_ne!(
            voice_hash("notify", "hello", "ahmet", 0, "tr"),
            voice_hash("ask", "hello", "ahmet", 0, "tr")
        );
    }
}
