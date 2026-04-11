# frozen_string_literal: true

# CIS 5.1 | CIS 5.5 | EC2.21 | NIST AC-17, SC-7
control 'secure-vpc-04' do
  impact 1.0
  title 'NACLs deny SSH and RDP from 0.0.0.0/0'
  desc 'No Network ACL associated with the VPC should allow ingress from
        0.0.0.0/0 to SSH (22) or RDP (3389) ports.'

  tag cis: %w[5.1 5.5]
  tag nist: %w[AC-17 SC-7]

  vpc_id = input('vpc_id')

  aws_network_acls.where(vpc_id: vpc_id).network_acl_ids.each do |acl_id|
    describe aws_network_acl(network_acl_id: acl_id) do
      it { should_not allow_in(port: 22, ipv4_range: '0.0.0.0/0') }
      it { should_not allow_in(port: 3389, ipv4_range: '0.0.0.0/0') }
    end
  end
end
