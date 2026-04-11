# frozen_string_literal: true

# CIS 5.3 | EC2.2 | CKV2_AWS_12 | FG_R00089 | NIST SC-7(5)
control 'secure-vpc-01' do
  impact 1.0
  title 'Default security group restricts all traffic'
  desc 'The default security group of the VPC must have zero ingress and
        zero egress rules. Any resource accidentally placed in the default
        SG will have no network access.'

  tag cis: '5.3'
  tag nist: %w[SC-7(5) AC-4]
  tag checkov: 'CKV2_AWS_12'

  vpc_id = input('vpc_id')

  describe aws_security_group(group_name: 'default', vpc_id: vpc_id) do
    it { should exist }
    its('inbound_rules_count') { should eq 0 }
    its('outbound_rules_count') { should eq 0 }
  end
end
