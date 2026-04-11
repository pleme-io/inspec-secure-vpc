# frozen_string_literal: true

# CKV_AWS_130 | AVD-AWS-0099 | NIST SC-7(16)
control 'secure-vpc-05' do
  impact 1.0
  title 'Private subnets do not auto-assign public IPs'
  desc 'Subnets tagged Tier=private must not auto-assign public IP addresses.
        This prevents accidental internet exposure of private workloads.'

  tag nist: %w[SC-7(16) SC-7]
  tag checkov: 'CKV_AWS_130'

  vpc_id = input('vpc_id')

  aws_subnets.where(vpc_id: vpc_id).subnet_ids.each do |subnet_id|
    subnet = aws_subnet(subnet_id: subnet_id)
    next unless subnet.tags&.dig('Tier') == 'private'

    describe subnet do
      its('map_public_ip_on_launch') { should eq false }
    end
  end
end
