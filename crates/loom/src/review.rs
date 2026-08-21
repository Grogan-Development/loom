//! Review findings, suggested-patch apply, and feature comment threads.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::contracts::RepositoryRevision;
use crate::features::{Feature, FeatureGate, FeatureStore};
use crate::{
    LoomError, NamespaceGrant, PersistentLoomStore, SourceCommitMutation, SourceCommitRequest,
    validate_path, validate_repository,
};

const MAX_REVIEW_BYTES: u64 = 4 * 1024 * 1024;
const MAX_REVIEWS: usize = 10_000;
const MAX_COMMENTS: usize = 10_000;
const MAX_COMMENT_BODY: usize = 16_384;

/// Lifecycle of one candidate review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewStatus {
    /// Created; no findings posted yet.
    Pending,
    /// Review Nero (or a human) is posting findings.
    InProgress,
    /// A verdict has been recorded.
    Completed,
}

/// Final judgment recorded on a completed review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewVerdict {
    /// Candidate may proceed to accept (when policy is blocking).
    Approve,
    /// Conversation only; treat as not approved for blocking policy.
    Comment,
    /// Author must address findings before accept.
    RequestChanges,
}

/// One review attached to a feature candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Review {
    /// Durable review identifier (UUID v7).
    pub id: String,
    /// Feature this review belongs to.
    pub feature_id: String,
    /// Candidate under review.
    pub candidate_id: String,
    /// Current review lifecycle state.
    pub status: ReviewStatus,
    /// Recorded verdict, if any.
    pub verdict: Option<ReviewVerdict>,
    /// Findings posted against this candidate.
    pub findings: Vec<Finding>,
}

/// One review finding, optionally carrying a suggested native patch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    /// Durable finding identifier (UUID v7).
    pub id: String,
    /// `error`, `warning`, or `note`.
    pub severity: String,
    /// Repository namespace the finding targets.
    pub repo: String,
    /// Repository-relative path.
    pub path: String,
    /// Inclusive start line (1-based).
    pub start_line: u32,
    /// Inclusive end line (1-based).
    pub end_line: u32,
    /// Human-readable finding text.
    pub message: String,
    /// Suggested mutations against the current candidate head.
    pub suggested_patch: Option<Vec<SourceCommitMutation>>,
    /// Revision produced when the suggestion was applied.
    pub applied: Option<RepositoryRevision>,
    /// Human or authoring-agent approval required before apply.
    pub approved: bool,
}

/// One comment on a feature, optionally threaded or bound to a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Comment {
    /// Durable comment identifier (UUID v7).
    pub id: String,
    /// Feature this comment belongs to.
    pub feature_id: String,
    /// `human` or `agent:<name>`.
    pub author: String,
    /// Comment body.
    pub body: String,
    /// Parent comment id, if this is a reply.
    pub in_reply_to: Option<String>,
    /// Finding this comment discusses, if any.
    pub finding_id: Option<String>,
    /// Unix seconds at creation.
    pub created_at: u64,
}

/// Start or get-or-create a review for the current candidate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewStart {
    /// Optional findings to record at start.
    #[serde(default)]
    pub findings: Vec<FindingInput>,
    /// Optional draft or final verdict.
    #[serde(default)]
    pub verdict: Option<ReviewVerdict>,
    /// Optional status override.
    #[serde(default)]
    pub status: Option<ReviewStatus>,
}

/// One finding as posted by review Nero or a human.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingInput {
    /// `error`, `warning`, or `note`.
    pub severity: String,
    /// Repository namespace.
    pub repo: String,
    /// Repository-relative path.
    pub path: String,
    /// Inclusive start line (1-based).
    pub start_line: u32,
    /// Inclusive end line (1-based).
    pub end_line: u32,
    /// Human-readable finding text.
    pub message: String,
    /// Suggested mutations against the current candidate head.
    #[serde(default)]
    pub suggested_patch: Option<Vec<SourceCommitMutation>>,
}

/// Append findings to an existing review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingsAppend {
    /// Findings to append.
    pub findings: Vec<FindingInput>,
}

/// Complete a review with a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewComplete {
    /// Final verdict.
    pub verdict: ReviewVerdict,
}

/// Apply a suggested patch, optionally approving in the same call.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingApply {
    /// When true, approve and apply in one call.
    #[serde(default)]
    pub approve: bool,
}

/// Create a comment on a feature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommentCreate {
    /// `human` or `agent:<name>`.
    pub author: String,
    /// Comment body.
    pub body: String,
    /// Parent comment id, if this is a reply.
    #[serde(default)]
    pub in_reply_to: Option<String>,
    /// Finding this comment discusses, if any.
    #[serde(default)]
    pub finding_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedReviews {
    schema_version: String,
    reviews: Vec<Review>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedComments {
    schema_version: String,
    comments: Vec<Comment>,
}

/// Durable review and comment catalog stored beside the Loom CAS.
#[derive(Debug, Clone)]
pub struct ReviewStore {
    store: PersistentLoomStore,
}

impl ReviewStore {
    /// Opens the review catalog inside an existing Loom dataset.
    #[must_use]
    pub const fn new(store: PersistentLoomStore) -> Self {
        Self { store }
    }

    /// Starts a review for the current candidate, or returns the existing one.
    ///
    /// The boolean is `true` when a new review was created.
    ///
    /// # Errors
    ///
    /// Returns when the feature or candidate is missing, findings are invalid,
    /// or durable I/O fails.
    pub fn start_or_get(
        &self,
        feature_id: &str,
        request: ReviewStart,
    ) -> Result<(Review, bool), LoomError> {
        let feature = FeatureStore::new(self.store.clone()).get(feature_id)?;
        let candidate_id = feature
            .candidate
            .as_ref()
            .ok_or(LoomError::InvalidSourceCommit)?
            .id
            .clone();
        let lock = self.store.exclusive_lock()?;
        let mut reviews = self.load_reviews()?;
        if let Some(existing) = latest_for_candidate(&reviews, feature_id, &candidate_id) {
            let review = existing.clone();
            File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
            return Ok((review, false));
        }
        let findings = request
            .findings
            .into_iter()
            .map(|input| finding_from_input(input, &feature))
            .collect::<Result<Vec<_>, _>>()?;
        let status = request.status.unwrap_or(if findings.is_empty() {
            ReviewStatus::Pending
        } else {
            ReviewStatus::InProgress
        });
        let review = Review {
            id: Uuid::now_v7().to_string(),
            feature_id: feature_id.to_owned(),
            candidate_id,
            status,
            verdict: request.verdict,
            findings,
        };
        if reviews.len() >= MAX_REVIEWS {
            return Err(LoomError::ResourceLimit);
        }
        reviews.insert(review.id.clone(), review.clone());
        self.write_reviews(&reviews)?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok((review, true))
    }

    /// Lists reviews for one feature, newest id first.
    ///
    /// # Errors
    ///
    /// Returns for durable I/O failure.
    pub fn list_for_feature(&self, feature_id: &str) -> Result<Vec<Review>, LoomError> {
        let lock = self.store.shared_lock()?;
        let mut reviews = self
            .load_reviews()?
            .into_values()
            .filter(|review| review.feature_id == feature_id)
            .collect::<Vec<_>>();
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        reviews.sort_by(|left, right| right.id.cmp(&left.id));
        Ok(reviews)
    }

    /// Appends findings to an existing review.
    ///
    /// # Errors
    ///
    /// Returns when the review is missing or completed, findings are invalid,
    /// or durable I/O fails.
    pub fn append_findings(
        &self,
        feature_id: &str,
        review_id: &str,
        request: FindingsAppend,
    ) -> Result<Review, LoomError> {
        if request.findings.is_empty() {
            return Err(LoomError::InvalidSourceCommit);
        }
        let feature = FeatureStore::new(self.store.clone()).get(feature_id)?;
        let findings = request
            .findings
            .into_iter()
            .map(|input| finding_from_input(input, &feature))
            .collect::<Result<Vec<_>, _>>()?;
        let lock = self.store.exclusive_lock()?;
        let mut reviews = self.load_reviews()?;
        let review = reviews
            .get_mut(review_id)
            .ok_or_else(|| unknown_review(review_id))?;
        if review.feature_id != feature_id {
            return Err(unknown_review(review_id));
        }
        if review.status == ReviewStatus::Completed {
            return Err(LoomError::InvalidSourceCommit);
        }
        review.findings.extend(findings);
        review.status = ReviewStatus::InProgress;
        let result = review.clone();
        self.write_reviews(&reviews)?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(result)
    }

    /// Records a verdict and marks the review completed.
    ///
    /// # Errors
    ///
    /// Returns when the review is missing or durable I/O fails.
    pub fn complete(
        &self,
        feature_id: &str,
        review_id: &str,
        request: ReviewComplete,
    ) -> Result<Review, LoomError> {
        let lock = self.store.exclusive_lock()?;
        let mut reviews = self.load_reviews()?;
        let review = reviews
            .get_mut(review_id)
            .ok_or_else(|| unknown_review(review_id))?;
        if review.feature_id != feature_id {
            return Err(unknown_review(review_id));
        }
        review.status = ReviewStatus::Completed;
        review.verdict = Some(request.verdict);
        let result = review.clone();
        self.write_reviews(&reviews)?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(result)
    }

    /// Marks a finding approved by a human or the authoring agent.
    ///
    /// # Errors
    ///
    /// Returns when the finding is missing or durable I/O fails.
    pub fn approve_finding(
        &self,
        feature_id: &str,
        finding_id: &str,
    ) -> Result<Finding, LoomError> {
        let lock = self.store.exclusive_lock()?;
        let mut reviews = self.load_reviews()?;
        let finding = set_finding_approved(&mut reviews, feature_id, finding_id)?;
        self.write_reviews(&reviews)?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(finding)
    }

    /// Applies an approved suggested patch to the current candidate head.
    ///
    /// Does not accept the feature and does not re-run CI. The candidate head
    /// for the finding's repository becomes the new revision.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSourceCommit` when the finding is not approved (unless
    /// `approve` is true), has no patch, or the candidate head is missing.
    pub fn apply_finding(
        &self,
        feature_id: &str,
        finding_id: &str,
        request: FindingApply,
    ) -> Result<Finding, LoomError> {
        if request.approve {
            self.approve_finding(feature_id, finding_id)?;
        }
        let (finding, base) = self.load_apply_context(feature_id, finding_id)?;
        if !finding.approved {
            return Err(LoomError::InvalidSourceCommit);
        }
        if let Some(applied) = finding.applied.clone() {
            return Ok(Finding {
                applied: Some(applied),
                ..finding
            });
        }
        let mut mutations = finding
            .suggested_patch
            .clone()
            .ok_or(LoomError::InvalidSourceCommit)?;
        if mutations.is_empty() {
            return Err(LoomError::InvalidSourceCommit);
        }
        mutations.sort_by(|left, right| left.path().cmp(right.path()));
        let grant = NamespaceGrant::new(BTreeSet::from([finding.repo.clone()]));
        let result = self.store.commit_source_changes(
            &grant,
            &SourceCommitRequest {
                schema_version: "v1".to_owned(),
                base,
                mutations,
            },
        )?;
        // Move the candidate head first: it re-checks the feature gate and
        // invalidates evidence. Marking the finding applied afterwards keeps
        // a head-update failure retryable instead of wedging the finding.
        FeatureStore::new(self.store.clone()).update_candidate_head(
            feature_id,
            &finding.repo,
            result.head.clone(),
        )?;
        self.record_applied(feature_id, finding_id, result.head.clone())?;
        Ok(Finding {
            applied: Some(result.head),
            approved: true,
            ..finding
        })
    }

    /// Lists comments for one feature, oldest first.
    ///
    /// # Errors
    ///
    /// Returns for durable I/O failure.
    pub fn list_comments(&self, feature_id: &str) -> Result<Vec<Comment>, LoomError> {
        let lock = self.store.shared_lock()?;
        let mut comments = self
            .load_comments()?
            .into_values()
            .filter(|comment| comment.feature_id == feature_id)
            .collect::<Vec<_>>();
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        comments.sort_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(comments)
    }

    /// Appends one comment to a feature thread.
    ///
    /// # Errors
    ///
    /// Returns when the author, body, reply target, or finding is invalid,
    /// or durable I/O fails.
    pub fn add_comment(
        &self,
        feature_id: &str,
        request: CommentCreate,
    ) -> Result<Comment, LoomError> {
        FeatureStore::new(self.store.clone()).get(feature_id)?;
        validate_comment(&request)?;
        let lock = self.store.exclusive_lock()?;
        let reviews = self.load_reviews()?;
        let mut comments = self.load_comments()?;
        if let Some(parent) = &request.in_reply_to {
            let exists = comments
                .get(parent)
                .is_some_and(|comment| comment.feature_id == feature_id);
            if !exists {
                return Err(unknown_comment(parent));
            }
        }
        if let Some(finding_id) = &request.finding_id
            && find_finding(&reviews, feature_id, finding_id).is_none()
        {
            return Err(unknown_finding(finding_id));
        }
        if comments.len() >= MAX_COMMENTS {
            return Err(LoomError::ResourceLimit);
        }
        let comment = Comment {
            id: Uuid::now_v7().to_string(),
            feature_id: feature_id.to_owned(),
            author: request.author,
            body: request.body,
            in_reply_to: request.in_reply_to,
            finding_id: request.finding_id,
            created_at: unix_now(),
        };
        comments.insert(comment.id.clone(), comment.clone());
        self.write_comments(&comments)?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(comment)
    }

    /// Returns whether Gate 2 accept may proceed under a blocking review policy.
    ///
    /// True when no review exists or the latest completed review approved.
    /// False when a review is pending or the latest verdict is not approve.
    /// Storage failures fail closed (`false`).
    #[must_use]
    pub fn blocking_ok(&self, feature_id: &str) -> bool {
        self.blocking_status(feature_id).unwrap_or(false)
    }

    fn blocking_status(&self, feature_id: &str) -> Result<bool, LoomError> {
        let mut reviews = self.list_for_feature(feature_id)?;
        if reviews.is_empty() {
            return Ok(true);
        }
        if reviews
            .iter()
            .any(|review| review.status != ReviewStatus::Completed)
        {
            return Ok(false);
        }
        reviews.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(reviews
            .last()
            .is_some_and(|review| review.verdict == Some(ReviewVerdict::Approve)))
    }

    fn load_apply_context(
        &self,
        feature_id: &str,
        finding_id: &str,
    ) -> Result<(Finding, RepositoryRevision), LoomError> {
        let feature = FeatureStore::new(self.store.clone()).get(feature_id)?;
        if feature.gate != FeatureGate::Approved {
            return Err(LoomError::InvalidSourceCommit);
        }
        let lock = self.store.shared_lock()?;
        let reviews = self.load_reviews()?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        let finding = find_finding(&reviews, feature_id, finding_id)
            .cloned()
            .ok_or_else(|| unknown_finding(finding_id))?;
        let head = candidate_head(&feature, &finding.repo)?.clone();
        Ok((finding, head))
    }

    fn record_applied(
        &self,
        feature_id: &str,
        finding_id: &str,
        head: RepositoryRevision,
    ) -> Result<(), LoomError> {
        let lock = self.store.exclusive_lock()?;
        let mut reviews = self.load_reviews()?;
        let finding = find_finding_mut(&mut reviews, feature_id, finding_id)
            .ok_or_else(|| unknown_finding(finding_id))?;
        finding.applied = Some(head);
        finding.approved = true;
        self.write_reviews(&reviews)?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)
    }

    fn load_reviews(&self) -> Result<BTreeMap<String, Review>, LoomError> {
        load_map(
            &self.store.root.join("reviews.json"),
            MAX_REVIEW_BYTES,
            MAX_REVIEWS,
            |bytes| {
                let persisted: PersistedReviews =
                    serde_json::from_slice(bytes).map_err(|_| LoomError::CorruptState)?;
                if persisted.schema_version != "v1" {
                    return Err(LoomError::CorruptState);
                }
                Ok(persisted.reviews)
            },
            |review| review.id.clone(),
        )
    }

    fn write_reviews(&self, reviews: &BTreeMap<String, Review>) -> Result<(), LoomError> {
        write_map(
            &self.store.root,
            "reviews.json",
            MAX_REVIEW_BYTES,
            PersistedReviews {
                schema_version: "v1".to_owned(),
                reviews: reviews.values().cloned().collect(),
            },
        )
    }

    fn load_comments(&self) -> Result<BTreeMap<String, Comment>, LoomError> {
        load_map(
            &self.store.root.join("comments.json"),
            MAX_REVIEW_BYTES,
            MAX_COMMENTS,
            |bytes| {
                let persisted: PersistedComments =
                    serde_json::from_slice(bytes).map_err(|_| LoomError::CorruptState)?;
                if persisted.schema_version != "v1" {
                    return Err(LoomError::CorruptState);
                }
                Ok(persisted.comments)
            },
            |comment| comment.id.clone(),
        )
    }

    fn write_comments(&self, comments: &BTreeMap<String, Comment>) -> Result<(), LoomError> {
        write_map(
            &self.store.root,
            "comments.json",
            MAX_REVIEW_BYTES,
            PersistedComments {
                schema_version: "v1".to_owned(),
                comments: comments.values().cloned().collect(),
            },
        )
    }
}

fn load_map<T, F, K>(
    path: &std::path::Path,
    maximum: u64,
    max_items: usize,
    parse: F,
    key: K,
) -> Result<BTreeMap<String, T>, LoomError>
where
    F: FnOnce(&[u8]) -> Result<Vec<T>, LoomError>,
    K: Fn(&T) -> String,
{
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let bytes = crate::read_bounded(path, maximum)?;
    let items = parse(&bytes)?;
    if items.len() > max_items {
        return Err(LoomError::CorruptState);
    }
    let mut map = BTreeMap::new();
    for item in items {
        if map.insert(key(&item), item).is_some() {
            return Err(LoomError::CorruptState);
        }
    }
    Ok(map)
}

fn write_map<T: Serialize>(
    root: &std::path::Path,
    file_name: &str,
    maximum: u64,
    persisted: T,
) -> Result<(), LoomError> {
    let bytes = serde_json::to_vec(&persisted).map_err(|_| LoomError::Serialization)?;
    if bytes.len() as u64 > maximum {
        return Err(LoomError::ResourceLimit);
    }
    crate::write_atomic(root, &root.join(file_name), &bytes, 0o600)
}

fn latest_for_candidate<'a>(
    reviews: &'a BTreeMap<String, Review>,
    feature_id: &str,
    candidate_id: &str,
) -> Option<&'a Review> {
    reviews
        .values()
        .filter(|review| review.feature_id == feature_id && review.candidate_id == candidate_id)
        .max_by(|left, right| left.id.cmp(&right.id))
}

fn find_finding<'a>(
    reviews: &'a BTreeMap<String, Review>,
    feature_id: &str,
    finding_id: &str,
) -> Option<&'a Finding> {
    reviews
        .values()
        .filter(|review| review.feature_id == feature_id)
        .find_map(|review| {
            review
                .findings
                .iter()
                .find(|finding| finding.id == finding_id)
        })
}

fn find_finding_mut<'a>(
    reviews: &'a mut BTreeMap<String, Review>,
    feature_id: &str,
    finding_id: &str,
) -> Option<&'a mut Finding> {
    reviews
        .values_mut()
        .filter(|review| review.feature_id == feature_id)
        .find_map(|review| {
            review
                .findings
                .iter_mut()
                .find(|finding| finding.id == finding_id)
        })
}

fn set_finding_approved(
    reviews: &mut BTreeMap<String, Review>,
    feature_id: &str,
    finding_id: &str,
) -> Result<Finding, LoomError> {
    let finding = find_finding_mut(reviews, feature_id, finding_id)
        .ok_or_else(|| unknown_finding(finding_id))?;
    finding.approved = true;
    Ok(finding.clone())
}

fn finding_from_input(input: FindingInput, feature: &Feature) -> Result<Finding, LoomError> {
    if !matches!(input.severity.as_str(), "error" | "warning" | "note") {
        return Err(LoomError::InvalidSourceCommit);
    }
    validate_repository(&input.repo)?;
    validate_path(&input.path)?;
    if input.start_line == 0 || input.end_line < input.start_line {
        return Err(LoomError::InvalidSourceCommit);
    }
    let message = input.message.trim();
    if message.is_empty() || message.len() > MAX_COMMENT_BODY {
        return Err(LoomError::InvalidSourceCommit);
    }
    let on_feature = feature
        .repositories
        .iter()
        .any(|binding| binding.base.repository == input.repo);
    if !on_feature {
        return Err(LoomError::InvalidSourceCommit);
    }
    if let Some(mutations) = &input.suggested_patch {
        if mutations.is_empty() {
            return Err(LoomError::InvalidSourceCommit);
        }
        let mut seen = BTreeSet::new();
        for mutation in mutations {
            let path = mutation.path();
            validate_path(path)?;
            if !seen.insert(path) {
                return Err(LoomError::DuplicateSourceMutation {
                    path: path.to_owned(),
                });
            }
        }
    }
    Ok(Finding {
        id: Uuid::now_v7().to_string(),
        severity: input.severity,
        repo: input.repo,
        path: input.path,
        start_line: input.start_line,
        end_line: input.end_line,
        message: message.to_owned(),
        suggested_patch: input.suggested_patch,
        applied: None,
        approved: false,
    })
}

fn candidate_head<'a>(
    feature: &'a Feature,
    repository: &str,
) -> Result<&'a RepositoryRevision, LoomError> {
    feature
        .candidate
        .as_ref()
        .and_then(|candidate| {
            candidate
                .repositories
                .iter()
                .find(|binding| binding.base.repository == repository)
        })
        .and_then(|binding| binding.head.as_ref())
        .ok_or(LoomError::InvalidSourceCommit)
}

fn validate_comment(request: &CommentCreate) -> Result<(), LoomError> {
    if !valid_author(&request.author) {
        return Err(LoomError::InvalidSourceCommit);
    }
    let body = request.body.trim();
    if body.is_empty() || body.len() > MAX_COMMENT_BODY {
        return Err(LoomError::InvalidSourceCommit);
    }
    Ok(())
}

fn valid_author(author: &str) -> bool {
    author == "human"
        || author.strip_prefix("agent:").is_some_and(|name| {
            (1..=128).contains(&name.len())
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
}

fn unknown_review(id: &str) -> LoomError {
    LoomError::UnknownRevision {
        repository: "reviews".to_owned(),
        revision: id.to_owned(),
    }
}

fn unknown_finding(id: &str) -> LoomError {
    LoomError::UnknownRevision {
        repository: "findings".to_owned(),
        revision: id.to_owned(),
    }
}

fn unknown_comment(id: &str) -> LoomError {
    LoomError::UnknownRevision {
        repository: "comments".to_owned(),
        revision: id.to_owned(),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
