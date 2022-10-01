// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/extras/sqlite/sqlite_persistent_reporting_and_nel_store.h"

#include <list>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/callback_helpers.h"
#include "base/feature_list.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/json/json_reader.h"
#include "base/json/json_string_value_serializer.h"
#include "base/metrics/histogram_macros.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/task_traits.h"
#include "base/thread_annotations.h"
#include "net/base/features.h"
#include "net/base/network_isolation_key.h"
#include "net/extras/sqlite/sqlite_persistent_store_backend_base.h"
#include "net/reporting/reporting_endpoint.h"
#include "sql/database.h"
#include "sql/meta_table.h"
#include "sql/statement.h"
#include "sql/transaction.h"
#include "url/origin.h"

namespace net {

namespace {
// Version 1 - 2019/03 - crrev.com/c/1504493, crrev.com/c/1560456
//
// Version 1 adds tables for NEL policies, Reporting endpoints, and Reporting
// endpoint groups.
//
// Version 2 - 2020/10 - https://crrev.com/c/2485253
//
// Version 2 adds NetworkIsolationKey fields to all entries. When migrating,
// existing entries get an empty NetworkIsolationKey value.
const int kCurrentVersionNumber = 2;
const int kCompatibleVersionNumber = 2;

// Enums for histograms:
// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.

// Outcome of initializing database
enum class InitializeDbOutcome {
  kFailedPathDoesNotExist = 0,
  kFailedOpenDbProblem = 1,
  kFailedMigrateDbProblem = 2,
  kSucceededNewDbFileCreated = 3,
  kSucceededExistingDbFileLoaded = 4,
  kMaxValue = kSucceededExistingDbFileLoaded,
};

// Outcome of updating the backing store
enum class BackingStoreUpdateOutcome {
  kSuccess = 0,
  kTrouble = 1,
  kFailure = 2,
  kMaxValue = kFailure
};

// Histogram names
const char kInitializeDbOutcomeHistogramName[] =
    "ReportingAndNEL.InitializeDBOutcome";
const char kBackingStoreUpdateOutcomeHistogramName[] =
    "ReportingAndNEL.BackingStoreUpdateOutcome";
const char kNumberOfLoadedNelPoliciesHistogramName[] =
    "ReportingAndNEL.NumberOfLoadedNELPolicies";
const char kNumberOfLoadedReportingEndpointsHistogramName[] =
    "ReportingAndNEL.NumberOfLoadedReportingEndpoints";
const char kNumberOfLoadedReportingEndpointGroupsHistogramName[] =
    "ReportingAndNEL.NumberOfLoadedReportingEndpointGroups";
const char kNumberOfLoadedNelPolicies2HistogramName[] =
    "ReportingAndNEL.NumberOfLoadedNELPolicies2";
const char kNumberOfLoadedReportingEndpoints2HistogramName[] =
    "ReportingAndNEL.NumberOfLoadedReportingEndpoints2";
const char kNumberOfLoadedReportingEndpointGroups2HistogramName[] =
    "ReportingAndNEL.NumberOfLoadedReportingEndpointGroups2";
}  // namespace

base::TaskPriority GetReportingAndNelStoreBackgroundSequencePriority() {
  return base::TaskPriority::USER_BLOCKING;
}

// Converts a NetworkIsolationKey to a string for serializing to disk. Returns
// false on failure, which happens for transient keys that should not be
// serialized to disk.
[[nodiscard]] bool NetworkIsolationKeyToString(
    const NetworkIsolationKey& network_isolation_key,
    std::string* out_string) {
  base::Value value;
  if (!network_isolation_key.ToValue(&value))
    return false;
  return JSONStringValueSerializer(out_string).Serialize(value);
}

// Attempts to convert a string returned by NetworkIsolationKeyToString() to
// a NetworkIsolationKey. Returns false on failure.
[[nodiscard]] bool NetworkIsolationKeyFromString(
    const std::string& string,
    NetworkIsolationKey* out_network_isolation_key) {
  absl::optional<base::Value> value = base::JSONReader::Read(string);
  if (!value)
    return false;

  if (!NetworkIsolationKey::FromValue(*value, out_network_isolation_key))
    return false;

  // If NetworkIsolationKeys are disabled for reporting and NEL, but the
  // NetworkIsolationKey is non-empty, ignore the entry. The entry will
  // still be in the on-disk database, in case NIKs are re-enabled, it just
  // won't be loaded into memory. The entry could still be loaded with an empty
  // NetworkIsolationKey, but that would require logic to resolve conflicts.
  if (!out_network_isolation_key->IsEmpty() &&
      !base::FeatureList::IsEnabled(
          features::kPartitionNelAndReportingByNetworkIsolationKey)) {
    *out_network_isolation_key = NetworkIsolationKey();
    return false;
  }

  return true;
}

class SQLitePersistentReportingAndNelStore::Backend
    : public SQLitePersistentStoreBackendBase {
 public:
  Backend(
      const base::FilePath& path,
      const scoped_refptr<base::SequencedTaskRunner>& client_task_runner,
      const scoped_refptr<base::SequencedTaskRunner>& background_task_runner)
      : SQLitePersistentStoreBackendBase(
            path,
            /* histogram_tag = */ "ReportingAndNEL",
            kCurrentVersionNumber,
            kCompatibleVersionNumber,
            background_task_runner,
            client_task_runner) {}

  Backend(const Backend&) = delete;
  Backend& operator=(const Backend&) = delete;

  void LoadNelPolicies(NelPoliciesLoadedCallback loaded_callback);
  void AddNelPolicy(const NetworkErrorLoggingService::NelPolicy& policy);
  void UpdateNelPolicyAccessTime(
      const NetworkErrorLoggingService::NelPolicy& policy);
  void DeleteNelPolicy(const NetworkErrorLoggingService::NelPolicy& policy);

  void LoadReportingClients(ReportingClientsLoadedCallback loaded_callback);
  void AddReportingEndpoint(const ReportingEndpoint& endpoint);
  void AddReportingEndpointGroup(const CachedReportingEndpointGroup& group);
  void UpdateReportingEndpointGroupAccessTime(
      const CachedReportingEndpointGroup& group);
  void UpdateReportingEndpointDetails(const ReportingEndpoint& endpoint);
  void UpdateReportingEndpointGroupDetails(
      const CachedReportingEndpointGroup& group);
  void DeleteReportingEndpoint(const ReportingEndpoint& endpoint);
  void DeleteReportingEndpointGroup(const CachedReportingEndpointGroup& group);

  // Gets the number of queued operations.
  size_t GetQueueLengthForTesting() const;

 private:
  ~Backend() override {
    DCHECK(nel_policy_pending_ops_.empty());
    DCHECK(reporting_endpoint_pending_ops_.empty());
    DCHECK(reporting_endpoint_group_pending_ops_.empty());
    DCHECK_EQ(0u, num_pending_);
  }

  // Represents a mutating operation to the database, specified by a type (add,
  // update access time, update data, or delete) and data representing the entry
  // in the database to be added/updated/deleted.
  template <typename DataType>
  class PendingOperation;

  // Types of PendingOperation. Here to avoid templatizing the enum.
  enum class PendingOperationType {
    ADD,
    UPDATE_ACCESS_TIME,
    UPDATE_DETAILS,
    DELETE
  };

  // List of pending operations for a particular entry in the database.
  template <typename DataType>
  using PendingOperationsVector =
      std::vector<std::unique_ptr<PendingOperation<DataType>>>;

  // A copy of the information relevant to a NEL policy.
  struct NelPolicyInfo;
  // A copy of the information relevant to a Reporting endpoint.
  struct ReportingEndpointInfo;
  // A copy of the information relevant to a Reporting endpoint group.
  struct ReportingEndpointGroupInfo;
  // TODO(chlily): add ReportingReportInfo.

  // Uniquely identifies an endpoint in the store.
  using ReportingEndpointKey = std::pair<ReportingEndpointGroupKey, GURL>;

  // Map of pending operations for each entry in the database.
  // Key types are: - url::Origin for NEL policies,
  //                - ReportingEndpointKey for Reporting endpoints,
  //                - ReportingEndpointGroupKey for Reporting endpoint groups
  //                  (defined in //net/reporting/reporting_endpoint.h).
  template <typename KeyType, typename DataType>
  using QueueType = std::map<KeyType, PendingOperationsVector<DataType>>;

  // SQLitePersistentStoreBackendBase implementation
  bool CreateDatabaseSchema() override;
  absl::optional<int> DoMigrateDatabaseSchema() override;
  void DoCommit() override;

  // Commit a pending operation pertaining to a NEL policy.
  // Returns true on success.
  bool CommitNelPolicyOperation(PendingOperation<NelPolicyInfo>* op);
  // Commit a pending operation pertaining to a Reporting endpoint.
  // Returns true on success.
  bool CommitReportingEndpointOperation(
      PendingOperation<ReportingEndpointInfo>* op);
  // Commit a pending operation pertaining to a Reporting endpoint group.
  // Returns true on success.
  bool CommitReportingEndpointGroupOperation(
      PendingOperation<ReportingEndpointGroupInfo>* op);

  // Add a pending operation to the appropriate queue.
  template <typename KeyType, typename DataType>
  void BatchOperation(KeyType key,
                      std::unique_ptr<PendingOperation<DataType>> po,
                      QueueType<KeyType, DataType>* queue);

  // If there are existing pending operations for a given key, potentially
  // remove some of the existing operations before adding |new_op|.
  // In particular, if |new_op| is a deletion, then all the previous pending
  // operations are made irrelevant and can be deleted. If |new_op| is an
  // update-access-time, and the last operation in |ops_for_key| is also an
  // update-access-time, then it can be discarded because |new_op| is about to
  // overwrite the access time with a new value anyway. Similarly for
  // update-details.
  template <typename DataType>
  void MaybeCoalesceOperations(PendingOperationsVector<DataType>* ops_for_key,
                               PendingOperation<DataType>* new_op)
      EXCLUSIVE_LOCKS_REQUIRED(lock_);

  // After adding a pending operation to one of the pending operations queues,
  // this method posts a task to commit all pending operations if we reached the
  // batch size, or starts a timer to commit after a time interval if we just
  // started a new batch. |num_pending| is the total number of pending
  // operations after the one we just added.
  void OnOperationBatched(size_t num_pending);

  // Loads NEL policies into a vector in the background, then posts a
  // task to the client task runner to call |loaded_callback| with the loaded
  // NEL policies.
  void LoadNelPoliciesAndNotifyInBackground(
      NelPoliciesLoadedCallback loaded_callback);

  // Calls |loaded_callback| with the loaded NEL policies (which may be empty if
  // loading was unsuccessful). If loading was successful, also report metrics.
  void CompleteLoadNelPoliciesAndNotifyInForeground(
      NelPoliciesLoadedCallback loaded_callback,
      std::vector<NetworkErrorLoggingService::NelPolicy> loaded_policies,
      bool load_success);

  // Loads Reporting endpoints and endpoint groups into two vectors in the
  // background, then posts a task to the client task runner to call
  // |loaded_callback| with the loaded endpoints and endpoint groups.
  void LoadReportingClientsAndNotifyInBackground(
      ReportingClientsLoadedCallback loaded_callback);

  // Calls |loaded_callback| with the loaded endpoints and endpoint groups
  // (which may be empty if loading was unsuccessful). If loading was
  // successful, also report metrics.
  void CompleteLoadReportingClientsAndNotifyInForeground(
      ReportingClientsLoadedCallback loaded_callback,
      std::vector<ReportingEndpoint> loaded_endpoints,
      std::vector<CachedReportingEndpointGroup> loaded_endpoint_groups,
      bool load_success);

  // SQLitePersistentStoreBackendBase:
  void RecordPathDoesNotExistProblem() override;
  void RecordOpenDBProblem() override;
  void RecordDBMigrationProblem() override;
  void RecordNewDBFile() override;
  void RecordDBLoaded() override;

  void RecordInitializeDBOutcome(InitializeDbOutcome outcome);
  void RecordBackingStoreUpdateOutcome(BackingStoreUpdateOutcome outcome);
  void RecordNumberOfLoadedNelPolicies(size_t count);
  void RecordNumberOfLoadedReportingEndpoints(size_t count);
  void RecordNumberOfLoadedReportingEndpointGroups(size_t count);

  // Total number of pending operations (may not match the sum of the number of
  // elements in the pending operations queues, due to operation coalescing).
  size_t num_pending_ GUARDED_BY(lock_) = 0;

  // Queue of pending operations pertaining to NEL policies, keyed on origin.
  QueueType<NetworkErrorLoggingService::NelPolicyKey, NelPolicyInfo>
      nel_policy_pending_ops_ GUARDED_BY(lock_);
  // Queue of pending operations pertaining to Reporting endpoints, keyed on
  // origin, group name, and url.
  QueueType<ReportingEndpointKey, ReportingEndpointInfo>
      reporting_endpoint_pending_ops_ GUARDED_BY(lock_);
  // Queue of pending operations pertaining to Reporting endpoint groups, keyed
  // on origin and group name.
  QueueType<ReportingEndpointGroupKey, ReportingEndpointGroupInfo>
      reporting_endpoint_group_pending_ops_ GUARDED_BY(lock_);

  // TODO(chlily): add reporting_report_pending_ops_ for Reporting reports.

  // Protects |num_pending_|, and all the pending operations queues.
  mutable base::Lock lock_;
};

namespace {

bool CreateV2NelPoliciesSchema(sql::Database* db) {
  DCHECK(!db->DoesTableExist("nel_policies"));

  std::string stmt =
      "CREATE TABLE nel_policies ("
      "  nik TEXT NOT NULL,"
      "  origin_scheme TEXT NOT NULL,"
      "  origin_host TEXT NOT NULL,"
      "  origin_port INTEGER NOT NULL,"
      "  received_ip_address TEXT NOT NULL,"
      "  group_name TEXT NOT NULL,"
      "  expires_us_since_epoch INTEGER NOT NULL,"
      "  success_fraction REAL NOT NULL,"
      "  failure_fraction REAL NOT NULL,"
      "  is_include_subdomains INTEGER NOT NULL,"
      "  last_access_us_since_epoch INTEGER NOT NULL,"
      // Each (origin, nik) specifies at most one NEL policy.
      "  UNIQUE (origin_scheme, origin_host, origin_port, nik)"
      ")";

  return db->Execute(stmt.c_str());
}

bool CreateV2ReportingEndpointsSchema(sql::Database* db) {
  DCHECK(!db->DoesTableExist("reporting_endpoints"));

  std::string stmt =
      "CREATE TABLE reporting_endpoints ("
      "  nik TEXT NOT NULL,"
      "  origin_scheme TEXT NOT NULL,"
      "  origin_host TEXT NOT NULL,"
      "  origin_port INTEGER NOT NULL,"
      "  group_name TEXT NOT NULL,"
      "  url TEXT NOT NULL,"
      "  priority INTEGER NOT NULL,"
      "  weight INTEGER NOT NULL,"
      // Each (origin, group, url, nik) tuple specifies at most one endpoint.
      "  UNIQUE (origin_scheme, origin_host, origin_port, group_name, url, nik)"
      ")";

  return db->Execute(stmt.c_str());
}

bool CreateV2ReportingEndpointGroupsSchema(sql::Database* db) {
  DCHECK(!db->DoesTableExist("reporting_endpoint_groups"));

  std::string stmt =
      "CREATE TABLE reporting_endpoint_groups ("
      "  nik TEXT NOT NULL,"
      "  origin_scheme TEXT NOT NULL,"
      "  origin_host TEXT NOT NULL,"
      "  origin_port INTEGER NOT NULL,"
      "  group_name TEXT NOT NULL,"
      "  is_include_subdomains INTEGER NOT NULL,"
      "  expires_us_since_epoch INTEGER NOT NULL,"
      "  last_access_us_since_epoch INTEGER NOT NULL,"
      // Each (origin, group, nik) tuple specifies at most one endpoint group.
      "  UNIQUE (origin_scheme, origin_host, origin_port, group_name, nik)"
      ")";

  return db->Execute(stmt.c_str());
}

}  // namespace

template <typename DataType>
class SQLitePersistentReportingAndNelStore::Backend::PendingOperation {
 public:
  PendingOperation(PendingOperationType type, DataType data)
      : type_(type), data_(std::move(data)) {}

  PendingOperationType type() const { return type_; }
  const DataType& data() const { return data_; }

 private:
  const PendingOperationType type_;
  const DataType data_;
};

// Makes a copy of the relevant information about a NelPolicy, stored in a
// form suitable for adding to the database.
// TODO(chlily): Add NIK.
struct SQLitePersistentReportingAndNelStore::Backend::NelPolicyInfo {
  // This should only be invoked through CreatePendingOperation().
  NelPolicyInfo(const NetworkErrorLoggingService::NelPolicy& nel_policy,
                std::string network_isolation_key_string)
      : network_isolation_key_string(std::move(network_isolation_key_string)),
        origin_scheme(nel_policy.key.origin.scheme()),
        origin_host(nel_policy.key.origin.host()),
        origin_port(nel_policy.key.origin.port()),
        received_ip_address(nel_policy.received_ip_address.ToString()),
        report_to(nel_policy.report_to),
        expires_us_since_epoch(
            nel_policy.expires.ToDeltaSinceWindowsEpoch().InMicroseconds()),
        success_fraction(nel_policy.success_fraction),
        failure_fraction(nel_policy.failure_fraction),
        is_include_subdomains(nel_policy.include_subdomains),
        last_access_us_since_epoch(
            nel_policy.last_used.ToDeltaSinceWindowsEpoch().InMicroseconds()) {}

  // Creates the specified operation for the given policy. Returns nullptr for
  // endpoints with transient NetworkIsolationKeys.
  static std::unique_ptr<PendingOperation<NelPolicyInfo>>
  CreatePendingOperation(
      PendingOperationType type,
      const NetworkErrorLoggingService::NelPolicy& nel_policy) {
    std::string network_isolation_key_string;
    if (!NetworkIsolationKeyToString(nel_policy.key.network_isolation_key,
                                     &network_isolation_key_string)) {
      return nullptr;
    }

    return std::make_unique<PendingOperation<NelPolicyInfo>>(
        type,
        NelPolicyInfo(nel_policy, std::move(network_isolation_key_string)));
  }

  // NetworkIsolationKey associated with the request that received the policy,
  // converted to a string via NetworkIsolationKeyToString().
  std::string network_isolation_key_string;

  // Origin the policy was received from.
  std::string origin_scheme;
  std::string origin_host;
  int origin_port = 0;

  // IP address of the server that the policy was received from.
  std::string received_ip_address;
  // The Reporting group which the policy specifies.
  std::string report_to;
  // When the policy expires, in microseconds since the Windows epoch.
  int64_t expires_us_since_epoch = 0;
  // Sampling fractions.
  double success_fraction = 0.0;
  double failure_fraction = 1.0;
  // Whether the policy applies to subdomains of the origin.
  bool is_include_subdomains = false;
  // Last time the policy was updated or used, in microseconds since the
  // Windows epoch.
  int64_t last_access_us_since_epoch = 0;
};

// Makes a copy of the relevant information about a ReportingEndpoint, stored in
// a form suitable for adding to the database.
struct SQLitePersistentReportingAndNelStore::Backend::ReportingEndpointInfo {
  // This should only be invoked through CreatePendingOperation().
  ReportingEndpointInfo(const ReportingEndpoint& endpoint,
                        std::string network_isolation_key_string)
      : network_isolation_key_string(std::move(network_isolation_key_string)),
        origin_scheme(endpoint.group_key.origin.scheme()),
        origin_host(endpoint.group_key.origin.host()),
        origin_port(endpoint.group_key.origin.port()),
        group_name(endpoint.group_key.group_name),
        url(endpoint.info.url.spec()),
        priority(endpoint.info.priority),
        weight(endpoint.info.weight) {}

  // Creates the specified operation for the given endpoint. Returns nullptr for
  // endpoints with transient NetworkIsolationKeys.
  static std::unique_ptr<PendingOperation<ReportingEndpointInfo>>
  CreatePendingOperation(PendingOperationType type,
                         const ReportingEndpoint& endpoint) {
    std::string network_isolation_key_string;
    if (!NetworkIsolationKeyToString(endpoint.group_key.network_isolation_key,
                                     &network_isolation_key_string)) {
      return nullptr;
    }

    return std::make_unique<PendingOperation<ReportingEndpointInfo>>(
        type, ReportingEndpointInfo(endpoint,
                                    std::move(network_isolation_key_string)));
  }

  // NetworkIsolationKey associated with the endpoint, converted to a string via
  // NetworkIsolationKeyToString().
  std::string network_isolation_key_string;

  // Origin the endpoint was received from.
  std::string origin_scheme;
  std::string origin_host;
  int origin_port = 0;

  // Name of the group the endpoint belongs to.
  std::string group_name;
  // URL of the endpoint.
  std::string url;
  // Priority of the endpoint.
  int priority = ReportingEndpoint::EndpointInfo::kDefaultPriority;
  // Weight of the endpoint.
  int weight = ReportingEndpoint::EndpointInfo::kDefaultWeight;
};

struct SQLitePersistentReportingAndNelStore::Backend::
    ReportingEndpointGroupInfo {
  ReportingEndpointGroupInfo(const CachedReportingEndpointGroup& group,
                             std::string network_isolation_key_string)
      : network_isolation_key_string(std::move(network_isolation_key_string)),
        origin_scheme(group.group_key.origin.scheme()),
        origin_host(group.group_key.origin.host()),
        origin_port(group.group_key.origin.port()),
        group_name(group.group_key.group_name),
        is_include_subdomains(group.include_subdomains ==
                              OriginSubdomains::INCLUDE),
        expires_us_since_epoch(
            group.expires.ToDeltaSinceWindowsEpoch().InMicroseconds()),
        last_access_us_since_epoch(
            group.last_used.ToDeltaSinceWindowsEpoch().InMicroseconds()) {}

  // Creates the specified operation for the given endpoint reporting group.
  // Returns nullptr for groups with transient NetworkIsolationKeys.
  static std::unique_ptr<PendingOperation<ReportingEndpointGroupInfo>>
  CreatePendingOperation(PendingOperationType type,
                         const CachedReportingEndpointGroup& group) {
    std::string network_isolation_key_string;
    if (!NetworkIsolationKeyToString(group.group_key.network_isolation_key,
                                     &network_isolation_key_string)) {
      return nullptr;
    }

    return std::make_unique<PendingOperation<ReportingEndpointGroupInfo>>(
        type, ReportingEndpointGroupInfo(
                  group, std::move(network_isolation_key_string)));
  }

  // NetworkIsolationKey associated with the endpoint group, converted to a
  // string via NetworkIsolationKeyToString().
  std::string network_isolation_key_string;

  // Origin the endpoint group was received from.
  std::string origin_scheme;
  std::string origin_host;
  int origin_port = 0;

  // Name of the group.
  std::string group_name;
  // Whether the group applies to subdomains of the origin.
  bool is_include_subdomains = false;
  // When the group expires, in microseconds since the Windows epoch.
  int64_t expires_us_since_epoch = 0;
  // Last time the group was updated or used, in microseconds since the Windows
  // epoch.
  int64_t last_access_us_since_epoch = 0;
};

void SQLitePersistentReportingAndNelStore::Backend::LoadNelPolicies(
    NelPoliciesLoadedCallback loaded_callback) {
  PostBackgroundTask(
      FROM_HERE, base::BindOnce(&Backend::LoadNelPoliciesAndNotifyInBackground,
                                this, std::move(loaded_callback)));
}

void SQLitePersistentReportingAndNelStore::Backend::AddNelPolicy(
    const NetworkErrorLoggingService::NelPolicy& policy) {
  auto po =
      NelPolicyInfo::CreatePendingOperation(PendingOperationType::ADD, policy);
  if (!po)
    return;
  BatchOperation(policy.key, std::move(po), &nel_policy_pending_ops_);
}

void SQLitePersistentReportingAndNelStore::Backend::UpdateNelPolicyAccessTime(
    const NetworkErrorLoggingService::NelPolicy& policy) {
  auto po = NelPolicyInfo::CreatePendingOperation(
      PendingOperationType::UPDATE_ACCESS_TIME, policy);
  if (!po)
    return;
  BatchOperation(policy.key, std::move(po), &nel_policy_pending_ops_);
}

void SQLitePersistentReportingAndNelStore::Backend::DeleteNelPolicy(
    const NetworkErrorLoggingService::NelPolicy& policy) {
  auto po = NelPolicyInfo::CreatePendingOperation(PendingOperationType::DELETE,
                                                  policy);
  if (!po)
    return;
  BatchOperation(policy.key, std::move(po), &nel_policy_pending_ops_);
}

void SQLitePersistentReportingAndNelStore::Backend::LoadReportingClients(
    ReportingClientsLoadedCallback loaded_callback) {
  PostBackgroundTask(
      FROM_HERE,
      base::BindOnce(&Backend::LoadReportingClientsAndNotifyInBackground, this,
                     std::move(loaded_callback)));
}

void SQLitePersistentReportingAndNelStore::Backend::AddReportingEndpoint(
    const ReportingEndpoint& endpoint) {
  auto po = ReportingEndpointInfo::CreatePendingOperation(
      PendingOperationType::ADD, endpoint);
  if (!po)
    return;
  ReportingEndpointKey key =
      std::make_pair(endpoint.group_key, endpoint.info.url);
  BatchOperation(std::move(key), std::move(po),
                 &reporting_endpoint_pending_ops_);
}

void SQLitePersistentReportingAndNelStore::Backend::AddReportingEndpointGroup(
    const CachedReportingEndpointGroup& group) {
  auto po = ReportingEndpointGroupInfo::CreatePendingOperation(
      PendingOperationType::ADD, group);
  if (!po)
    return;
  BatchOperation(group.group_key, std::move(po),
                 &reporting_endpoint_group_pending_ops_);
}

void SQLitePersistentReportingAndNelStore::Backend::
    UpdateReportingEndpointGroupAccessTime(
        const CachedReportingEndpointGroup& group) {
  auto po = ReportingEndpointGroupInfo::CreatePendingOperation(
      PendingOperationType::UPDATE_ACCESS_TIME, group);
  if (!po)
    return;
  BatchOperation(group.group_key, std::move(po),
                 &reporting_endpoint_group_pending_ops_);
}

void SQLitePersistentReportingAndNelStore::Backend::
    UpdateReportingEndpointDetails(const ReportingEndpoint& endpoint) {
  auto po = ReportingEndpointInfo::CreatePendingOperation(
      PendingOperationType::UPDATE_DETAILS, endpoint);
  if (!po)
    return;
  ReportingEndpointKey key =
      std::make_pair(endpoint.group_key, endpoint.info.url);
  BatchOperation(std::move(key), std::move(po),
                 &reporting_endpoint_pending_ops_);
}

void SQLitePersistentReportingAndNelStore::Backend::
    UpdateReportingEndpointGroupDetails(
        const CachedReportingEndpointGroup& group) {
  auto po = ReportingEndpointGroupInfo::CreatePendingOperation(
      PendingOperationType::UPDATE_DETAILS, group);
  if (!po)
    return;
  BatchOperation(group.group_key, std::move(po),
                 &reporting_endpoint_group_pending_ops_);
}

void SQLitePersistentReportingAndNelStore::Backend::DeleteReportingEndpoint(
    const ReportingEndpoint& endpoint) {
  auto po = ReportingEndpointInfo::CreatePendingOperation(
      PendingOperationType::DELETE, endpoint);
  if (!po)
    return;
  ReportingEndpointKey key =
      std::make_pair(endpoint.group_key, endpoint.info.url);
  BatchOperation(std::move(key), std::move(po),
                 &reporting_endpoint_pending_ops_);
}

void SQLitePersistentReportingAndNelStore::Backend::
    DeleteReportingEndpointGroup(const CachedReportingEndpointGroup& group) {
  auto po = ReportingEndpointGroupInfo::CreatePendingOperation(
      PendingOperationType::DELETE, group);
  if (!po)
    return;
  BatchOperation(group.group_key, std::move(po),
                 &reporting_endpoint_group_pending_ops_);
}

size_t SQLitePersistentReportingAndNelStore::Backend::GetQueueLengthForTesting()
    const {
  size_t count = 0;
  {
    base::AutoLock locked(lock_);
    for (auto& key_and_pending_ops : nel_policy_pending_ops_) {
      count += key_and_pending_ops.second.size();
    }
    for (auto& key_and_pending_ops : reporting_endpoint_pending_ops_) {
      count += key_and_pending_ops.second.size();
    }
    for (auto& key_and_pending_ops : reporting_endpoint_group_pending_ops_) {
      count += key_and_pending_ops.second.size();
    }
  }
  return count;
}

bool SQLitePersistentReportingAndNelStore::Backend::CreateDatabaseSchema() {
  if (!db()->DoesTableExist("nel_policies") &&
      !CreateV2NelPoliciesSchema(db())) {
    return false;
  }

  if (!db()->DoesTableExist("reporting_endpoints") &&
      !CreateV2ReportingEndpointsSchema(db())) {
    return false;
  }

  if (!db()->DoesTableExist("reporting_endpoint_groups") &&
      !CreateV2ReportingEndpointGroupsSchema(db())) {
    return false;
  }

  // TODO(chlily): Initialize tables for Reporting reports.

  return true;
}

absl::optional<int>
SQLitePersistentReportingAndNelStore::Backend::DoMigrateDatabaseSchema() {
  int cur_version = meta_table()->GetVersionNumber();

  // Migrate from version 1 to version 2.
  //
  // For migration purposes, the NetworkIsolationKey field of the stored
  // policies will be populated with an empty list, which corresponds to an
  // empty NIK. This matches the behavior when NIKs are disabled. This will
  // result in effectively clearing all policies once NIKs are enabled, at
  // which point the the migration code should just be switched to deleting
  // the old tables instead.
  if (cur_version == 1) {
    sql::Transaction transaction(db());
    if (!transaction.Begin())
      return absl::nullopt;

    // Migrate NEL policies table.
    if (!db()->Execute("DROP TABLE IF EXISTS nel_policies_old; "
                       "ALTER TABLE nel_policies RENAME TO nel_policies_old")) {
      return absl::nullopt;
    }
    if (!CreateV2NelPoliciesSchema(db()))
      return absl::nullopt;
    // clang-format off
    // The "report_to" field is renamed to "group_name" for consistency with
    // the other tables.
    std::string nel_policies_migrate_stmt =
      "INSERT INTO nel_policies (nik, origin_scheme, origin_host, "
      "  origin_port, group_name, received_ip_address, expires_us_since_epoch, "
      "  success_fraction, failure_fraction, is_include_subdomains, "
      "  last_access_us_since_epoch) "
      "SELECT '[]', origin_scheme, origin_host, origin_port, "
      "  report_to, received_ip_address, expires_us_since_epoch, "
      "  success_fraction, failure_fraction, is_include_subdomains, "
      "  last_access_us_since_epoch "
      "FROM nel_policies_old" ;
    // clang-format on
    if (!db()->Execute(nel_policies_migrate_stmt.c_str()))
      return absl::nullopt;
    if (!db()->Execute("DROP TABLE nel_policies_old"))
      return absl::nullopt;

    // Migrate Reporting endpoints table.
    if (!db()->Execute("DROP TABLE IF EXISTS reporting_endpoints_old; "
                       "ALTER TABLE reporting_endpoints RENAME TO "
                       "reporting_endpoints_old")) {
      return absl::nullopt;
    }
    if (!CreateV2ReportingEndpointsSchema(db()))
      return absl::nullopt;
    // clang-format off
    std::string reporting_endpoints_migrate_stmt =
      "INSERT INTO reporting_endpoints (nik,  origin_scheme, origin_host, "
      "  origin_port, group_name, url, priority, weight) "
      "SELECT '[]', origin_scheme, origin_host, origin_port, group_name, "
      "  url, priority, weight "
      "FROM reporting_endpoints_old" ;
    // clang-format on
    if (!db()->Execute(reporting_endpoints_migrate_stmt.c_str()))
      return absl::nullopt;
    if (!db()->Execute("DROP TABLE reporting_endpoints_old"))
      return absl::nullopt;

    // Migrate Reporting endpoint groups table.
    if (!db()->Execute("DROP TABLE IF EXISTS reporting_endpoint_groups_old; "
                       "ALTER TABLE reporting_endpoint_groups RENAME TO "
                       "reporting_endpoint_groups_old")) {
      return absl::nullopt;
    }
    if (!CreateV2ReportingEndpointGroupsSchema(db()))
      return absl::nullopt;
    // clang-format off
    std::string reporting_endpoint_groups_migrate_stmt =
      "INSERT INTO reporting_endpoint_groups (nik,  origin_scheme, "
      "  origin_host, origin_port, group_name, is_include_subdomains, "
      "  expires_us_since_epoch, last_access_us_since_epoch) "
      "SELECT '[]', origin_scheme, origin_host, origin_port, "
      "  group_name, is_include_subdomains, expires_us_since_epoch, "
      "  last_access_us_since_epoch "
      "FROM reporting_endpoint_groups_old" ;
    // clang-format on
    if (!db()->Execute(reporting_endpoint_groups_migrate_stmt.c_str()))
      return absl::nullopt;
    if (!db()->Execute("DROP TABLE reporting_endpoint_groups_old"))
      return absl::nullopt;

    ++cur_version;
    meta_table()->SetVersionNumber(cur_version);
    meta_table()->SetCompatibleVersionNumber(
        std::min(cur_version, kCompatibleVersionNumber));
    transaction.Commit();
  }

  // Future database upgrade statements go here.

  return absl::make_optional(cur_version);
}

void SQLitePersistentReportingAndNelStore::Backend::DoCommit() {
  QueueType<NetworkErrorLoggingService::NelPolicyKey, NelPolicyInfo>
      nel_policy_ops;
  QueueType<ReportingEndpointKey, ReportingEndpointInfo> reporting_endpoint_ops;
  QueueType<ReportingEndpointGroupKey, ReportingEndpointGroupInfo>
      reporting_endpoint_group_ops;
  size_t op_count = 0;
  {
    base::AutoLock locked(lock_);
    nel_policy_pending_ops_.swap(nel_policy_ops);
    reporting_endpoint_pending_ops_.swap(reporting_endpoint_ops);
    reporting_endpoint_group_pending_ops_.swap(reporting_endpoint_group_ops);
    // TODO(chlily): swap out pending operations queue for Reporting reports.
    op_count = num_pending_;
    num_pending_ = 0;
  }
  if (!db() || op_count == 0)
    return;

  sql::Transaction transaction(db());
  if (!transaction.Begin())
    return;

  bool ops_success = true;

  // Commit all the NEL policy operations.
  for (const auto& origin_and_nel_policy_ops : nel_policy_ops) {
    const PendingOperationsVector<NelPolicyInfo>& ops_for_origin =
        origin_and_nel_policy_ops.second;
    for (const std::unique_ptr<PendingOperation<NelPolicyInfo>>& nel_policy_op :
         ops_for_origin) {
      ops_success &= CommitNelPolicyOperation(nel_policy_op.get());
    }
  }

  // Commit all the Reporting endpoint operations.
  for (const auto& key_and_reporting_endpoint_ops : reporting_endpoint_ops) {
    const PendingOperationsVector<ReportingEndpointInfo>& ops_for_key =
        key_and_reporting_endpoint_ops.second;
    for (const std::unique_ptr<PendingOperation<ReportingEndpointInfo>>&
             reporting_endpoint_op : ops_for_key) {
      ops_success &=
          CommitReportingEndpointOperation(reporting_endpoint_op.get());
    }
  }

  // Commit all the Reporting endpoint group operations.
  for (const auto& key_and_reporting_endpoint_group_ops :
       reporting_endpoint_group_ops) {
    const PendingOperationsVector<ReportingEndpointGroupInfo>& ops_for_key =
        key_and_reporting_endpoint_group_ops.second;
    for (const std::unique_ptr<PendingOperation<ReportingEndpointGroupInfo>>&
             reporting_endpoint_group_op : ops_for_key) {
      ops_success &= CommitReportingEndpointGroupOperation(
          reporting_endpoint_group_op.get());
    }
  }

  // TODO(chlily): Commit operations pertaining to Reporting reports.

  bool commit_success = transaction.Commit();
  BackingStoreUpdateOutcome outcome =
      (commit_success && ops_success)
          ? BackingStoreUpdateOutcome::kSuccess
          : commit_success ? BackingStoreUpdateOutcome::kTrouble
                           : BackingStoreUpdateOutcome::kFailure;
  RecordBackingStoreUpdateOutcome(outcome);
}

bool SQLitePersistentReportingAndNelStore::Backend::CommitNelPolicyOperation(
    PendingOperation<NelPolicyInfo>* op) {
  DCHECK_EQ(1, db()->transaction_nesting());

  sql::Statement add_statement(db()->GetCachedStatement(
      SQL_FROM_HERE,
      "INSERT INTO nel_policies (nik, origin_scheme, origin_host, origin_port, "
      "received_ip_address, group_name, expires_us_since_epoch, "
      "success_fraction, failure_fraction, is_include_subdomains, "
      "last_access_us_since_epoch) VALUES (?,?,?,?,?,?,?,?,?,?,?)"));
  if (!add_statement.is_valid())
    return false;

  sql::Statement update_access_statement(db()->GetCachedStatement(
      SQL_FROM_HERE,
      "UPDATE nel_policies SET last_access_us_since_epoch=? WHERE "
      "nik=? AND origin_scheme=? AND origin_host=? AND origin_port=?"));
  if (!update_access_statement.is_valid())
    return false;

  sql::Statement del_statement(db()->GetCachedStatement(
      SQL_FROM_HERE,
      "DELETE FROM nel_policies WHERE "
      "nik=? AND origin_scheme=? AND origin_host=? AND origin_port=?"));
  if (!del_statement.is_valid())
    return false;

  const NelPolicyInfo& nel_policy_info = op->data();

  switch (op->type()) {
    case PendingOperationType::ADD:
      add_statement.Reset(true);
      add_statement.BindString(0, nel_policy_info.network_isolation_key_string);
      add_statement.BindString(1, nel_policy_info.origin_scheme);
      add_statement.BindString(2, nel_policy_info.origin_host);
      add_statement.BindInt(3, nel_policy_info.origin_port);
      add_statement.BindString(4, nel_policy_info.received_ip_address);
      add_statement.BindString(5, nel_policy_info.report_to);
      add_statement.BindInt64(6, nel_policy_info.expires_us_since_epoch);
      add_statement.BindDouble(7, nel_policy_info.success_fraction);
      add_statement.BindDouble(8, nel_policy_info.failure_fraction);
      add_statement.BindBool(9, nel_policy_info.is_include_subdomains);
      add_statement.BindInt64(10, nel_policy_info.last_access_us_since_epoch);
      if (!add_statement.Run()) {
        DLOG(WARNING) << "Could not add a NEL policy to the DB.";
        return false;
      }
      break;

    case PendingOperationType::UPDATE_ACCESS_TIME:
      update_access_statement.Reset(true);
      update_access_statement.BindInt64(
          0, nel_policy_info.last_access_us_since_epoch);
      update_access_statement.BindString(
          1, nel_policy_info.network_isolation_key_string);
      update_access_statement.BindString(2, nel_policy_info.origin_scheme);
      update_access_statement.BindString(3, nel_policy_info.origin_host);
      update_access_statement.BindInt(4, nel_policy_info.origin_port);
      if (!update_access_statement.Run()) {
        DLOG(WARNING)
            << "Could not update NEL policy last access time in the DB.";
        return false;
      }
      break;

    case PendingOperationType::DELETE:
      del_statement.Reset(true);
      del_statement.BindString(0, nel_policy_info.network_isolation_key_string);
      del_statement.BindString(1, nel_policy_info.origin_scheme);
      del_statement.BindString(2, nel_policy_info.origin_host);
      del_statement.BindInt(3, nel_policy_info.origin_port);
      if (!del_statement.Run()) {
        DLOG(WARNING) << "Could not delete a NEL policy from the DB.";
        return false;
      }
      break;

    default:
      // There are no UPDATE_DETAILS operations for NEL policies.
      // TODO(chlily): Maybe add the ability to update details as opposed to
      // removing and re-adding every time; it might be slightly more efficient.
      NOTREACHED();
      break;
  }

  return true;
}

bool SQLitePersistentReportingAndNelStore::Backend::
    CommitReportingEndpointOperation(
        PendingOperation<ReportingEndpointInfo>* op) {
  DCHECK_EQ(1, db()->transaction_nesting());

  sql::Statement add_statement(db()->GetCachedStatement(
      SQL_FROM_HERE,
      "INSERT INTO reporting_endpoints (nik, origin_scheme, origin_host, "
      "origin_port, group_name, url, priority, weight) "
      "VALUES (?,?,?,?,?,?,?,?)"));
  if (!add_statement.is_valid())
    return false;

  sql::Statement update_details_statement(db()->GetCachedStatement(
      SQL_FROM_HERE,
      "UPDATE reporting_endpoints SET priority=?, weight=? WHERE "
      "nik=? AND origin_scheme=? AND origin_host=? AND origin_port=? "
      "AND group_name=? AND url=?"));
  if (!update_details_statement.is_valid())
    return false;

  sql::Statement del_statement(db()->GetCachedStatement(
      SQL_FROM_HERE,
      "DELETE FROM reporting_endpoints WHERE "
      "nik=? AND origin_scheme=? AND origin_host=? AND origin_port=? "
      "AND group_name=? AND url=?"));
  if (!del_statement.is_valid())
    return false;

  const ReportingEndpointInfo& reporting_endpoint_info = op->data();

  switch (op->type()) {
    case PendingOperationType::ADD:
      add_statement.Reset(true);
      add_statement.BindString(
          0, reporting_endpoint_info.network_isolation_key_string);
      add_statement.BindString(1, reporting_endpoint_info.origin_scheme);
      add_statement.BindString(2, reporting_endpoint_info.origin_host);
      add_statement.BindInt(3, reporting_endpoint_info.origin_port);
      add_statement.BindString(4, reporting_endpoint_info.group_name);
      add_statement.BindString(5, reporting_endpoint_info.url);
      add_statement.BindInt(6, reporting_endpoint_info.priority);
      add_statement.BindInt(7, reporting_endpoint_info.weight);
      if (!add_statement.Run()) {
        DLOG(WARNING) << "Could not add a Reporting endpoint to the DB.";
        return false;
      }
      break;

    case PendingOperationType::UPDATE_DETAILS:
      update_details_statement.Reset(true);
      update_details_statement.BindInt(0, reporting_endpoint_info.priority);
      update_details_statement.BindInt(1, reporting_endpoint_info.weight);
      update_details_statement.BindString(
          2, reporting_endpoint_info.network_isolation_key_string);
      update_details_statement.BindString(
          3, reporting_endpoint_info.origin_scheme);
      update_details_statement.BindString(4,
                                          reporting_endpoint_info.origin_host);
      update_details_statement.BindInt(5, reporting_endpoint_info.origin_port);
      update_details_statement.BindString(6,
                                          reporting_endpoint_info.group_name);
      update_details_statement.BindString(7, reporting_endpoint_info.url);
      if (!update_details_statement.Run()) {
        DLOG(WARNING)
            << "Could not update Reporting endpoint details in the DB.";
        return false;
      }
      break;

    case PendingOperationType::DELETE:
      del_statement.Reset(true);
      del_statement.BindString(
          0, reporting_endpoint_info.network_isolation_key_string);
      del_statement.BindString(1, reporting_endpoint_info.origin_scheme);
      del_statement.BindString(2, reporting_endpoint_info.origin_host);
      del_statement.BindInt(3, reporting_endpoint_info.origin_port);
      del_statement.BindString(4, reporting_endpoint_info.group_name);
      del_statement.BindString(5, reporting_endpoint_info.url);
      if (!del_statement.Run()) {
        DLOG(WARNING) << "Could not delete a Reporting endpoint from the DB.";
        return false;
      }
      break;

    default:
      // There are no UPDATE_ACCESS_TIME operations for Reporting endpoints
      // because their access times are not tracked.
      NOTREACHED();
      break;
  }

  return true;
}

bool SQLitePersistentReportingAndNelStore::Backend::
    CommitReportingEndpointGroupOperation(
        PendingOperation<ReportingEndpointGroupInfo>* op) {
  DCHECK_EQ(1, db()->transaction_nesting());

  sql::Statement add_statement(db()->GetCachedStatement(
      SQL_FROM_HERE,
      "INSERT INTO reporting_endpoint_groups (nik, origin_scheme, origin_host, "
      "origin_port, group_name, is_include_subdomains, expires_us_since_epoch, "
      "last_access_us_since_epoch) VALUES (?,?,?,?,?,?,?,?)"));
  if (!add_statement.is_valid())
    return false;

  sql::Statement update_access_statement(db()->GetCachedStatement(
      SQL_FROM_HERE,
      "UPDATE reporting_endpoint_groups SET last_access_us_since_epoch=? WHERE "
      "nik=? AND origin_scheme=? AND origin_host=? AND origin_port=? AND "
      "group_name=?"));
  if (!update_access_statement.is_valid())
    return false;

  sql::Statement update_details_statement(db()->GetCachedStatement(
      SQL_FROM_HERE,
      "UPDATE reporting_endpoint_groups SET is_include_subdomains=?, "
      "expires_us_since_epoch=?, last_access_us_since_epoch=? WHERE "
      "nik=? AND origin_scheme=? AND origin_host=? AND origin_port=? AND "
      "group_name=?"));
  if (!update_details_statement.is_valid())
    return false;

  sql::Statement del_statement(
      db()->GetCachedStatement(SQL_FROM_HERE,
                               "DELETE FROM reporting_endpoint_groups WHERE "
                               "nik=? AND origin_scheme=? AND origin_host=? "
                               "AND origin_port=? AND group_name=?"));
  if (!del_statement.is_valid())
    return false;

  const ReportingEndpointGroupInfo& reporting_endpoint_group_info = op->data();

  switch (op->type()) {
    case PendingOperationType::ADD:
      add_statement.Reset(true);
      add_statement.BindString(
          0, reporting_endpoint_group_info.network_isolation_key_string);
      add_statement.BindString(1, reporting_endpoint_group_info.origin_scheme);
      add_statement.BindString(2, reporting_endpoint_group_info.origin_host);
      add_statement.BindInt(3, reporting_endpoint_group_info.origin_port);
      add_statement.BindString(4, reporting_endpoint_group_info.group_name);
      add_statement.BindBool(
          5, reporting_endpoint_group_info.is_include_subdomains);
      add_statement.BindInt64(
          6, reporting_endpoint_group_info.expires_us_since_epoch);
      add_statement.BindInt64(
          7, reporting_endpoint_group_info.last_access_us_since_epoch);
      if (!add_statement.Run()) {
        DLOG(WARNING) << "Could not add a Reporting endpoint group to the DB.";
        return false;
      }
      break;

    case PendingOperationType::UPDATE_ACCESS_TIME:
      update_access_statement.Reset(true);
      update_access_statement.BindInt64(
          0, reporting_endpoint_group_info.last_access_us_since_epoch);
      update_access_statement.BindString(
          1, reporting_endpoint_group_info.network_isolation_key_string);
      update_access_statement.BindString(
          2, reporting_endpoint_group_info.origin_scheme);
      update_access_statement.BindString(
          3, reporting_endpoint_group_info.origin_host);
      update_access_statement.BindInt(
          4, reporting_endpoint_group_info.origin_port);
      update_access_statement.BindString(
          5, reporting_endpoint_group_info.group_name);
      if (!update_access_statement.Run()) {
        DLOG(WARNING)
            << "Could not update Reporting endpoint group last access "
               "time in the DB.";
        return false;
      }
      break;

    case PendingOperationType::UPDATE_DETAILS:
      update_details_statement.Reset(true);
      update_details_statement.BindBool(
          0, reporting_endpoint_group_info.is_include_subdomains);
      update_details_statement.BindInt64(
          1, reporting_endpoint_group_info.expires_us_since_epoch);
      update_details_statement.BindInt64(
          2, reporting_endpoint_group_info.last_access_us_since_epoch);
      update_details_statement.BindString(
          3, reporting_endpoint_group_info.network_isolation_key_string);
      update_details_statement.BindString(
          4, reporting_endpoint_group_info.origin_scheme);
      update_details_statement.BindString(
          5, reporting_endpoint_group_info.origin_host);
      update_details_statement.BindInt(
          6, reporting_endpoint_group_info.origin_port);
      update_details_statement.BindString(
          7, reporting_endpoint_group_info.group_name);
      if (!update_details_statement.Run()) {
        DLOG(WARNING)
            << "Could not update Reporting endpoint group details in the DB.";
        return false;
      }
      break;

    case PendingOperationType::DELETE:
      del_statement.Reset(true);
      del_statement.BindString(
          0, reporting_endpoint_group_info.network_isolation_key_string);
      del_statement.BindString(1, reporting_endpoint_group_info.origin_scheme);
      del_statement.BindString(2, reporting_endpoint_group_info.origin_host);
      del_statement.BindInt(3, reporting_endpoint_group_info.origin_port);
      del_statement.BindString(4, reporting_endpoint_group_info.group_name);
      if (!del_statement.Run()) {
        DLOG(WARNING)
            << "Could not delete a Reporting endpoint group from the DB.";
        return false;
      }
      break;
  }

  return true;
}

template <typename KeyType, typename DataType>
void SQLitePersistentReportingAndNelStore::Backend::BatchOperation(
    KeyType key,
    std::unique_ptr<PendingOperation<DataType>> po,
    QueueType<KeyType, DataType>* queue) {
  DCHECK(!background_task_runner()->RunsTasksInCurrentSequence());

  size_t num_pending;
  {
    base::AutoLock locked(lock_);

    std::pair<typename QueueType<KeyType, DataType>::iterator, bool>
        iter_and_result = queue->insert(std::make_pair(
            std::move(key), PendingOperationsVector<DataType>()));
    PendingOperationsVector<DataType>* ops_for_key =
        &iter_and_result.first->second;
    // If the insert failed, then we already have operations for this
    // key, so we try to coalesce the new operation with the existing ones.
    if (!iter_and_result.second)
      MaybeCoalesceOperations(ops_for_key, po.get());
    ops_for_key->push_back(std::move(po));
    // Note that num_pending_ counts number of calls to Batch*Operation(), not
    // the current length of the queue; this is intentional to guarantee
    // progress, as the length of the queue may decrease in some cases.
    num_pending = ++num_pending_;
  }

  OnOperationBatched(num_pending);
}

template <typename DataType>
void SQLitePersistentReportingAndNelStore::Backend::MaybeCoalesceOperations(
    PendingOperationsVector<DataType>* ops_for_key,
    PendingOperation<DataType>* new_op) {
  DCHECK(!ops_for_key->empty());

  switch (new_op->type()) {
    case PendingOperationType::DELETE:
      // A delete makes all previous operations irrelevant.
      ops_for_key->clear();
      break;

    case PendingOperationType::UPDATE_ACCESS_TIME:
      if (ops_for_key->back()->type() ==
          PendingOperationType::UPDATE_ACCESS_TIME) {
        // Updating the access time twice in a row is equivalent to just the
        // latter update.
        ops_for_key->pop_back();
      }
      break;

    case PendingOperationType::UPDATE_DETAILS:
      while (!ops_for_key->empty() &&
             // Updating the details twice in a row is equivalent to just the
             // latter update.
             (ops_for_key->back()->type() ==
                  PendingOperationType::UPDATE_DETAILS ||
              // UPDATE_DETAILS also updates the access time, so either type of
              // update operation can be discarded.
              ops_for_key->back()->type() ==
                  PendingOperationType::UPDATE_ACCESS_TIME)) {
        ops_for_key->pop_back();
      }
      break;

    case PendingOperationType::ADD:
      // Nothing special is done for an add operation. If it is overwriting an
      // existing entry, it will be preceded by at most one delete.
      DCHECK_LE(ops_for_key->size(), 1u);
      break;
  }
}

void SQLitePersistentReportingAndNelStore::Backend::OnOperationBatched(
    size_t num_pending) {
  DCHECK(!background_task_runner()->RunsTasksInCurrentSequence());
  // Commit every 30 seconds.
  static const int kCommitIntervalMs = 30 * 1000;
  // Commit right away if we have more than 512 outstanding operations.
  static const size_t kCommitAfterBatchSize = 512;

  if (num_pending == 1) {
    // We've gotten our first entry for this batch, fire off the timer.
    if (!background_task_runner()->PostDelayedTask(
            FROM_HERE, base::BindOnce(&Backend::Commit, this),
            base::Milliseconds(kCommitIntervalMs))) {
      NOTREACHED() << "background_task_runner_ is not running.";
    }
  } else if (num_pending >= kCommitAfterBatchSize) {
    // We've reached a big enough batch, fire off a commit now.
    PostBackgroundTask(FROM_HERE, base::BindOnce(&Backend::Commit, this));
  }
}

// TODO(chlily): Discard expired policies when loading, discard and record
// problem if loaded policy is malformed.
void SQLitePersistentReportingAndNelStore::Backend::
    LoadNelPoliciesAndNotifyInBackground(
        NelPoliciesLoadedCallback loaded_callback) {
  DCHECK(background_task_runner()->RunsTasksInCurrentSequence());

  std::vector<NetworkErrorLoggingService::NelPolicy> loaded_policies;
  if (!InitializeDatabase()) {
    PostClientTask(
        FROM_HERE,
        base::BindOnce(&Backend::CompleteLoadNelPoliciesAndNotifyInForeground,
                       this, std::move(loaded_callback),
                       std::move(loaded_policies), false /* load_success */));
    return;
  }

  sql::Statement smt(db()->GetUniqueStatement(
      "SELECT nik, origin_scheme, origin_host, origin_port, "
      "received_ip_address, group_name, expires_us_since_epoch, "
      "success_fraction, failure_fraction, is_include_subdomains, "
      "last_access_us_since_epoch FROM nel_policies"));
  if (!smt.is_valid()) {
    Reset();
    PostClientTask(
        FROM_HERE,
        base::BindOnce(&Backend::CompleteLoadNelPoliciesAndNotifyInForeground,
                       this, std::move(loaded_callback),
                       std::move(loaded_policies), false /* load_success */));
    return;
  }

  while (smt.Step()) {
    // Attempt to reconstitute a NEL policy from the fields stored in the
    // database.
    NetworkIsolationKey network_isolation_key;
    if (!NetworkIsolationKeyFromString(smt.ColumnString(0),
                                       &network_isolation_key))
      continue;
    NetworkErrorLoggingService::NelPolicy policy;
    policy.key = NetworkErrorLoggingService::NelPolicyKey(
        network_isolation_key, url::Origin::CreateFromNormalizedTuple(
                                   /* origin_scheme = */ smt.ColumnString(1),
                                   /* origin_host = */ smt.ColumnString(2),
                                   /* origin_port = */ smt.ColumnInt(3)));
    if (!policy.received_ip_address.AssignFromIPLiteral(smt.ColumnString(4)))
      policy.received_ip_address = IPAddress();
    policy.report_to = smt.ColumnString(5);
    policy.expires = base::Time::FromDeltaSinceWindowsEpoch(
        base::Microseconds(smt.ColumnInt64(6)));
    policy.success_fraction = smt.ColumnDouble(7);
    policy.failure_fraction = smt.ColumnDouble(8);
    policy.include_subdomains = smt.ColumnBool(9);
    policy.last_used = base::Time::FromDeltaSinceWindowsEpoch(
        base::Microseconds(smt.ColumnInt64(10)));

    loaded_policies.push_back(std::move(policy));
  }

  PostClientTask(
      FROM_HERE,
      base::BindOnce(&Backend::CompleteLoadNelPoliciesAndNotifyInForeground,
                     this, std::move(loaded_callback),
                     std::move(loaded_policies), true /* load_success */));
}

void SQLitePersistentReportingAndNelStore::Backend::
    CompleteLoadNelPoliciesAndNotifyInForeground(
        NelPoliciesLoadedCallback loaded_callback,
        std::vector<NetworkErrorLoggingService::NelPolicy> loaded_policies,
        bool load_success) {
  DCHECK(client_task_runner()->RunsTasksInCurrentSequence());

  if (load_success) {
    RecordNumberOfLoadedNelPolicies(loaded_policies.size());
  } else {
    DCHECK(loaded_policies.empty());
  }

  std::move(loaded_callback).Run(std::move(loaded_policies));
}

void SQLitePersistentReportingAndNelStore::Backend::
    LoadReportingClientsAndNotifyInBackground(
        ReportingClientsLoadedCallback loaded_callback) {
  DCHECK(background_task_runner()->RunsTasksInCurrentSequence());

  std::vector<ReportingEndpoint> loaded_endpoints;
  std::vector<CachedReportingEndpointGroup> loaded_endpoint_groups;
  if (!InitializeDatabase()) {
    PostClientTask(
        FROM_HERE,
        base::BindOnce(
            &Backend::CompleteLoadReportingClientsAndNotifyInForeground, this,
            std::move(loaded_callback), std::move(loaded_endpoints),
            std::move(loaded_endpoint_groups), false /* load_success */));
    return;
  }

  sql::Statement endpoints_statement(db()->GetUniqueStatement(
      "SELECT nik, origin_scheme, origin_host, origin_port, group_name, "
      "url, priority, weight FROM reporting_endpoints"));
  sql::Statement endpoint_groups_statement(db()->GetUniqueStatement(
      "SELECT nik, origin_scheme, origin_host, origin_port, group_name, "
      "is_include_subdomains, expires_us_since_epoch, "
      "last_access_us_since_epoch FROM reporting_endpoint_groups"));
  if (!endpoints_statement.is_valid() ||
      !endpoint_groups_statement.is_valid()) {
    Reset();
    PostClientTask(
        FROM_HERE,
        base::BindOnce(
            &Backend::CompleteLoadReportingClientsAndNotifyInForeground, this,
            std::move(loaded_callback), std::move(loaded_endpoints),
            std::move(loaded_endpoint_groups), false /* load_success */));
    return;
  }

  while (endpoints_statement.Step()) {
    // Attempt to reconstitute a ReportingEndpoint from the fields stored in the
    // database.
    NetworkIsolationKey network_isolation_key;
    if (!NetworkIsolationKeyFromString(endpoints_statement.ColumnString(0),
                                       &network_isolation_key))
      continue;
    ReportingEndpointGroupKey group_key(
        network_isolation_key,
        /* origin = */
        url::Origin::CreateFromNormalizedTuple(
            /* origin_scheme = */ endpoints_statement.ColumnString(1),
            /* origin_host = */ endpoints_statement.ColumnString(2),
            /* origin_port = */ endpoints_statement.ColumnInt(3)),
        /* group_name = */ endpoints_statement.ColumnString(4));
    ReportingEndpoint::EndpointInfo endpoint_info;
    endpoint_info.url = GURL(endpoints_statement.ColumnString(5));
    endpoint_info.priority = endpoints_statement.ColumnInt(6);
    endpoint_info.weight = endpoints_statement.ColumnInt(7);

    loaded_endpoints.emplace_back(std::move(group_key),
                                  std::move(endpoint_info));
  }

  while (endpoint_groups_statement.Step()) {
    // Attempt to reconstitute a CachedReportingEndpointGroup from the fields
    // stored in the database.
    NetworkIsolationKey network_isolation_key;
    if (!NetworkIsolationKeyFromString(
            endpoint_groups_statement.ColumnString(0), &network_isolation_key))
      continue;
    ReportingEndpointGroupKey group_key(
        network_isolation_key,
        /* origin = */
        url::Origin::CreateFromNormalizedTuple(
            /* origin_scheme = */ endpoint_groups_statement.ColumnString(1),
            /* origin_host = */ endpoint_groups_statement.ColumnString(2),
            /* origin_port = */ endpoint_groups_statement.ColumnInt(3)),
        /* group_name = */ endpoint_groups_statement.ColumnString(4));
    OriginSubdomains include_subdomains =
        endpoint_groups_statement.ColumnBool(5) ? OriginSubdomains::INCLUDE
                                                : OriginSubdomains::EXCLUDE;
    base::Time expires = base::Time::FromDeltaSinceWindowsEpoch(
        base::Microseconds(endpoint_groups_statement.ColumnInt64(6)));
    base::Time last_used = base::Time::FromDeltaSinceWindowsEpoch(
        base::Microseconds(endpoint_groups_statement.ColumnInt64(7)));

    loaded_endpoint_groups.emplace_back(std::move(group_key),
                                        include_subdomains, expires, last_used);
  }

  PostClientTask(
      FROM_HERE,
      base::BindOnce(
          &Backend::CompleteLoadReportingClientsAndNotifyInForeground, this,
          std::move(loaded_callback), std::move(loaded_endpoints),
          std::move(loaded_endpoint_groups), true /* load_success */));
}

void SQLitePersistentReportingAndNelStore::Backend::
    CompleteLoadReportingClientsAndNotifyInForeground(
        ReportingClientsLoadedCallback loaded_callback,
        std::vector<ReportingEndpoint> loaded_endpoints,
        std::vector<CachedReportingEndpointGroup> loaded_endpoint_groups,
        bool load_success) {
  DCHECK(client_task_runner()->RunsTasksInCurrentSequence());

  if (load_success) {
    RecordNumberOfLoadedReportingEndpoints(loaded_endpoints.size());
    RecordNumberOfLoadedReportingEndpointGroups(loaded_endpoint_groups.size());
  } else {
    DCHECK(loaded_endpoints.empty());
    DCHECK(loaded_endpoint_groups.empty());
  }

  std::move(loaded_callback)
      .Run(std::move(loaded_endpoints), std::move(loaded_endpoint_groups));
}

void SQLitePersistentReportingAndNelStore::Backend::
    RecordPathDoesNotExistProblem() {
  RecordInitializeDBOutcome(InitializeDbOutcome::kFailedPathDoesNotExist);
}

void SQLitePersistentReportingAndNelStore::Backend::RecordOpenDBProblem() {
  RecordInitializeDBOutcome(InitializeDbOutcome::kFailedOpenDbProblem);
}

void SQLitePersistentReportingAndNelStore::Backend::RecordDBMigrationProblem() {
  RecordInitializeDBOutcome(InitializeDbOutcome::kFailedMigrateDbProblem);
}

void SQLitePersistentReportingAndNelStore::Backend::RecordNewDBFile() {
  RecordInitializeDBOutcome(InitializeDbOutcome::kSucceededNewDbFileCreated);
}

void SQLitePersistentReportingAndNelStore::Backend::RecordDBLoaded() {
  RecordInitializeDBOutcome(
      InitializeDbOutcome::kSucceededExistingDbFileLoaded);
}

void SQLitePersistentReportingAndNelStore::Backend::RecordInitializeDBOutcome(
    InitializeDbOutcome outcome) {
  UMA_HISTOGRAM_ENUMERATION(kInitializeDbOutcomeHistogramName, outcome);
}

void SQLitePersistentReportingAndNelStore::Backend::
    RecordBackingStoreUpdateOutcome(BackingStoreUpdateOutcome outcome) {
  UMA_HISTOGRAM_ENUMERATION(kBackingStoreUpdateOutcomeHistogramName, outcome);
}

void SQLitePersistentReportingAndNelStore::Backend::
    RecordNumberOfLoadedNelPolicies(size_t count) {
  // The NetworkErrorLoggingService stores up to 1000 policies.
  UMA_HISTOGRAM_COUNTS_1000(kNumberOfLoadedNelPoliciesHistogramName, count);
  // TODO(crbug.com/1165308): Remove this metric once the investigation is done.
  UMA_HISTOGRAM_COUNTS_10000(kNumberOfLoadedNelPolicies2HistogramName, count);
}

void SQLitePersistentReportingAndNelStore::Backend::
    RecordNumberOfLoadedReportingEndpoints(size_t count) {
  // The ReportingCache stores up to 1000 endpoints.
  UMA_HISTOGRAM_COUNTS_1000(kNumberOfLoadedReportingEndpointsHistogramName,
                            count);
  // TODO(crbug.com/1165308): Remove this metric once the investigation is done.
  UMA_HISTOGRAM_COUNTS_10000(kNumberOfLoadedReportingEndpoints2HistogramName,
                             count);
}

void SQLitePersistentReportingAndNelStore::Backend::
    RecordNumberOfLoadedReportingEndpointGroups(size_t count) {
  // The ReportingCache stores up to 1000 endpoints, and there is at least one
  // endpoint per group.
  UMA_HISTOGRAM_COUNTS_1000(kNumberOfLoadedReportingEndpointGroupsHistogramName,
                            count);
  // TODO(crbug.com/1165308): Remove this metric once the investigation is done.
  UMA_HISTOGRAM_COUNTS_10000(
      kNumberOfLoadedReportingEndpointGroups2HistogramName, count);
}

SQLitePersistentReportingAndNelStore::SQLitePersistentReportingAndNelStore(
    const base::FilePath& path,
    const scoped_refptr<base::SequencedTaskRunner>& client_task_runner,
    const scoped_refptr<base::SequencedTaskRunner>& background_task_runner)
    : backend_(base::MakeRefCounted<Backend>(path,
                                             client_task_runner,
                                             background_task_runner)) {}

SQLitePersistentReportingAndNelStore::~SQLitePersistentReportingAndNelStore() {
  backend_->Close();
}

void SQLitePersistentReportingAndNelStore::LoadNelPolicies(
    NelPoliciesLoadedCallback loaded_callback) {
  DCHECK(!loaded_callback.is_null());
  backend_->LoadNelPolicies(base::BindOnce(
      &SQLitePersistentReportingAndNelStore::CompleteLoadNelPolicies,
      weak_factory_.GetWeakPtr(), std::move(loaded_callback)));
}

void SQLitePersistentReportingAndNelStore::AddNelPolicy(
    const NetworkErrorLoggingService::NelPolicy& policy) {
  backend_->AddNelPolicy(policy);
}

void SQLitePersistentReportingAndNelStore::UpdateNelPolicyAccessTime(
    const NetworkErrorLoggingService::NelPolicy& policy) {
  backend_->UpdateNelPolicyAccessTime(policy);
}

void SQLitePersistentReportingAndNelStore::DeleteNelPolicy(
    const NetworkErrorLoggingService::NelPolicy& policy) {
  backend_->DeleteNelPolicy(policy);
}

void SQLitePersistentReportingAndNelStore::LoadReportingClients(
    ReportingClientsLoadedCallback loaded_callback) {
  DCHECK(!loaded_callback.is_null());
  backend_->LoadReportingClients(base::BindOnce(
      &SQLitePersistentReportingAndNelStore::CompleteLoadReportingClients,
      weak_factory_.GetWeakPtr(), std::move(loaded_callback)));
}

void SQLitePersistentReportingAndNelStore::AddReportingEndpoint(
    const ReportingEndpoint& endpoint) {
  backend_->AddReportingEndpoint(endpoint);
}

void SQLitePersistentReportingAndNelStore::AddReportingEndpointGroup(
    const CachedReportingEndpointGroup& group) {
  backend_->AddReportingEndpointGroup(group);
}

void SQLitePersistentReportingAndNelStore::
    UpdateReportingEndpointGroupAccessTime(
        const CachedReportingEndpointGroup& group) {
  backend_->UpdateReportingEndpointGroupAccessTime(group);
}

void SQLitePersistentReportingAndNelStore::UpdateReportingEndpointDetails(
    const ReportingEndpoint& endpoint) {
  backend_->UpdateReportingEndpointDetails(endpoint);
}

void SQLitePersistentReportingAndNelStore::UpdateReportingEndpointGroupDetails(
    const CachedReportingEndpointGroup& group) {
  backend_->UpdateReportingEndpointGroupDetails(group);
}

void SQLitePersistentReportingAndNelStore::DeleteReportingEndpoint(
    const ReportingEndpoint& endpoint) {
  backend_->DeleteReportingEndpoint(endpoint);
}

void SQLitePersistentReportingAndNelStore::DeleteReportingEndpointGroup(
    const CachedReportingEndpointGroup& group) {
  backend_->DeleteReportingEndpointGroup(group);
}

void SQLitePersistentReportingAndNelStore::Flush() {
  backend_->Flush(base::DoNothing());
}

size_t SQLitePersistentReportingAndNelStore::GetQueueLengthForTesting() const {
  return backend_->GetQueueLengthForTesting();
}

void SQLitePersistentReportingAndNelStore::CompleteLoadNelPolicies(
    NelPoliciesLoadedCallback callback,
    std::vector<NetworkErrorLoggingService::NelPolicy> policies) {
  std::move(callback).Run(std::move(policies));
}

void SQLitePersistentReportingAndNelStore::CompleteLoadReportingClients(
    ReportingClientsLoadedCallback callback,
    std::vector<ReportingEndpoint> endpoints,
    std::vector<CachedReportingEndpointGroup> endpoint_groups) {
  std::move(callback).Run(std::move(endpoints), std::move(endpoint_groups));
}

}  // namespace net
