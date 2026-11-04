import sys
sys.path[:0]=['/opt/nockapp/research/zkid', '/usr/lib/python3.14/site-packages']
if sys.argv[1:] == ['selfcheck']:
 from ticket_capsule_probe_v1 import run
 import json
 print(json.dumps(run(['authorship.py', 'authorship_v5.py', 'aws_transport.py', 'base_evm.py', 'base_fees.py', 'base_finality.py', 'base_protocol.py', 'base_rpc.py', 'base_transactions.py', 'budget.py', 'count_authorship_v5.py', 'count_pipeline.py', 'count_policy.py', 'count_protocol.py', 'count_receipts.py', 'count_state.py', 'credential.py', 'domain_authority.py', 'domain_pipeline.py', 'domain_post_authority.py', 'domain_posts.py', 'domain_state.py', 'historical_authorship_v5.py', 'indexed_authorship_v5.py', 'permissionless_contracts.py', 'permissionless_index.py', 'policy.py', 'post_scope.py', 'provisioning.py', 'public_bundle.py', 'public_bundle_v4.py', 'public_bundle_v5.py', 'public_content_v5.py', 'public_reader_v5.py', 'public_s3.py', 'public_s3_endpoints.py', 'public_s3_v5.py', 'public_storage_budget.py', 'setup_aws_sdk.py', 'ticket_aws_credentials_v1.py', 'ticket_backend_boot_v1.py', 'ticket_backend_records_v1.py', 'ticket_backend_resources_v1.py', 'ticket_backend_tls_boot_v2.py', 'ticket_bindings_v1.py', 'ticket_ca_supervised_v1.py', 'ticket_capsule_probe_v1.py', 'ticket_capsule_v1.py', 'ticket_credential_broker_v1.py', 'ticket_first_journal_entrypoint_v1', 'ticket_first_journal_process_v1', 'ticket_first_journal_v1', 'ticket_host_tls_ca_v1.py', 'ticket_host_tls_daemon_v1.py', 'ticket_host_tls_delivery_v1.py', 'ticket_host_tls_renewal_v1.py', 'ticket_issuance_v1.py', 'ticket_journal_v2.py', 'ticket_metadata_firewall_v1.py', 'ticket_native_v1.py', 'ticket_offer_v1.py', 'ticket_payment_v1.py', 'ticket_plan_admission_v1.py', 'ticket_plan_admission_v2.py', 'ticket_private_s3_v1.py', 'ticket_process_v1.py', 'ticket_publication_queue_v2.py', 'ticket_publication_v2.py', 'ticket_refund_payout_v1.py', 'ticket_refund_rpc_v1.py', 'ticket_refund_service_v1.py', 'ticket_refund_v1.py', 'ticket_refund_vault_v1.py', 'ticket_renewing_process_v2.py', 'ticket_server_v1.py', 'ticket_server_v2.py', 'ticket_service_plan_v1.py', 'ticket_service_plan_v2.py', 'ticket_service_v2.py', 'ticket_supervised_v1.py', 'ticket_supervised_v2.py', 'ticket_tls_ca_credentials_v1.py', 'ticket_transport_v2.py', 'wallet_authorship.py', 'wallet_authorship_v5.py', 'workload_sessions.py'],'/opt/nockapp/research/zkid/local/ticket-tools/nockapp-ticket-worker-v1','80dc330e2fe970d776ba82404ef7d39cef6fb477c62cc894e846c08169b99af6','/opt/nockapp/research/zkid/local/authorship-native/debug/nockapp-authorship-v4'),sort_keys=True))
elif len(sys.argv)>1 and sys.argv[1]=='systemd':
 sys.argv.pop(1)
 from ticket_supervised_v2 import main
 raise SystemExit(main())
elif len(sys.argv)>1 and sys.argv[1]=='review':
 sys.argv.pop(1)
 from ticket_plan_admission_v1 import main
 raise SystemExit(main())
elif len(sys.argv)>1 and sys.argv[1]=='review-with-ca':
 sys.argv.pop(1)
 from ticket_plan_admission_v2 import main
 raise SystemExit(main())
elif len(sys.argv)>1 and sys.argv[1]=='ca-systemd':
 sys.argv.pop(1)
 from ticket_ca_supervised_v1 import main
 raise SystemExit(main())
elif len(sys.argv)>1 and sys.argv[1]=='role-tls-systemd':
 sys.argv.pop(1)
 from ticket_renewing_process_v2 import main
 raise SystemExit(main())
else:
 from ticket_process_v1 import main
 raise SystemExit(main())
