# frozen_string_literal: true

# CIS 5.6 | EC2.6 | CKV2_AWS_11 | FG_R00350 | NIST AU-2, AU-12
control 'secure-vpc-02' do
  impact 1.0
  title 'VPC Flow Logs are enabled and delivering'
  desc 'Every VPC must have flow logs enabled to capture network traffic
        for security monitoring and incident response.'

  tag cis: '5.6'
  tag nist: %w[AU-2 AU-12 SI-4]
  tag checkov: 'CKV2_AWS_11'

  only_if('Flow logs not expected') { input('flow_logs_enabled') == 'true' }

  vpc_id = input('vpc_id')

  aws_flow_log(vpc_id: vpc_id).tap do |fl|
    describe fl do
      it { should exist }
      its('deliver_logs_status') { should eq 'SUCCESS' }
    end
  end
end

# NIST AU-11 — Audit record retention
control 'secure-vpc-03' do
  impact 0.7
  title 'Flow log CloudWatch log group has correct retention'
  desc 'Flow log retention must match the expected value (7d dev, 90d prod).'

  tag nist: %w[AU-11 AU-6]

  only_if('Flow logs not expected') { input('flow_logs_enabled') == 'true' }

  prefix = input('vpc_name_prefix')
  log_group_name = "/vpc/#{prefix}/flow-logs"

  describe aws_cloudwatch_log_group(log_group_name: log_group_name) do
    it { should exist }
    its('retention_in_days') { should eq input('expected_retention_days') }
  end
end
