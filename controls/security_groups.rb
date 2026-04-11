# frozen_string_literal: true

# CIS 5.2 | EC2.13 | EC2.14 | CKV_AWS_24 | CKV_AWS_25 | NIST SC-7(11)
control 'secure-vpc-09' do
  impact 1.0
  title 'No security group allows SSH or RDP from 0.0.0.0/0'
  desc 'Security groups must not allow ingress from 0.0.0.0/0 to
        remote administration ports (SSH 22, RDP 3389).'

  tag cis: '5.2'
  tag nist: %w[SC-7(11) AC-17]
  tag checkov: %w[CKV_AWS_24 CKV_AWS_25]

  vpc_id = input('vpc_id')

  aws_security_groups.where(vpc_id: vpc_id).group_ids.each do |sg_id|
    describe aws_security_group(group_id: sg_id) do
      it { should_not allow_in(port: 22, ipv4_range: '0.0.0.0/0') }
      it { should_not allow_in(port: 3389, ipv4_range: '0.0.0.0/0') }
    end
  end
end
