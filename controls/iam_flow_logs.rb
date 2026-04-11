# frozen_string_literal: true

# NIST AU-6 — Flow log IAM role has minimal permissions
control 'secure-vpc-10' do
  impact 0.7
  title 'Flow log IAM role has minimal permissions'
  desc 'The IAM role used by VPC Flow Logs must trust only the
        vpc-flow-logs.amazonaws.com service principal.'

  tag nist: %w[AU-6 AC-6]

  only_if('Flow logs not expected') { input('flow_logs_enabled') == 'true' }

  prefix = input('vpc_name_prefix')
  role_name = "#{prefix}-vpc-flow-log-role"

  describe aws_iam_role(role_name: role_name) do
    it { should exist }
  end
end
