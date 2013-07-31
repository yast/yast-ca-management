# encoding: utf-8

# ***************************************************************************
#
# Copyright (c) 2004 - 2012 Novell, Inc.
# All Rights Reserved.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2 of the GNU General Public License as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.   See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, contact Novell, Inc.
#
# To contact Novell about this file by physical or electronic mail,
# you may find current contact information at www.novell.com
#
# ***************************************************************************
# File:        modules/CaMgm.ycp
# Package:     CA Management
# Summary:     Managing CAs, Requests and Certificate
# Authors:     Stefan Schubert <schubi@suse.de>
#
# $Id$
#
# Representation of the configuration of CAs
# Input and output routines.
require "yast"

module Yast
  class CaMgmClass < Module
    def main
      textdomain "ca-management"

      Yast.import "Progress"
      Yast.import "Report"
      Yast.import "Summary"

      # AutoYaST Settings Map
      @autoYaSTSettings = {}
      @autoYaSTModified = false


      # sequence for creating CA and certificates
      @certificateSequence = {
        "ws_start"          => "new_certinit",
        "new_certinit"      => { :next => "new_certSaveDef", :abort => :abort },
        "new_certSaveDef"   => { :next => "new_cert1", :abort => :abort },
        "new_cert1"         => {
          :next  => "new_cert2",
          :again => "new_cert1",
          :abort => :abort
        },
        "new_cert2"         => {
          :next            => "new_cert3",
          :abort           => :abort,
          :back            => "new_cert1",
          :advancedOptions => "new_cert_advanced"
        },
        "new_cert3"         => {
          :next  => :abort,
          :abort => :abort,
          :back  => "new_cert2"
        },
        "new_cert_advanced" => { :abort => :abort, :back => "new_cert3" }
      }


      # selected default type
      @currentDefault = "Sub CA"
      @initializeDefault = true


      # selected CA
      @currentCA = ""

      # selected certificate
      @currentCertificate = ""

      # selected Request
      @currentRequest = ""
      # Request Extentions of the current Request
      @requestKind = ""
      @requestSubject = ""
      @requestExtentionValue = {}
      @slectedRequestExtention = []
      @validRequestExtention = [
        "nsCaRevocationUrl",
        "nsCaPolicyUrl",
        "nsBaseUrl",
        "nsRenewalUrl",
        "nsRevocationUrl",
        "nsCertType",
        "nsComment",
        "nsSslServerName",
        "crlDistributionPoints",
        "basicConstraints",
        "keyUsage",
        "issuserAltName",
        "subjectAltName",
        "authorityKeyIdentifier",
        "extendedKeyUsage",
        "subjectKeyIdentifier",
        "certificatePolicies"
      ]

      # Password map for CA
      @passwdMap = {}

      # settings for proposal
      @prop_settingsWritten = false
      @prop_ca_commonNameChanged = false
      @prop_ca_commonName = ""
      @prop_server_commonNameChanged = false
      @prop_server_commonName = ""
      @prop_CANameChanged = false
      @prop_CAName = ""
      @prop_countryChanged = false
      @prop_country = "GB"
      @prop_passwordChanged = false
      @prop_password = ""
      @prop_emailChanged = false
      @prop_email = ""
      @prop_organisation = ""
      @prop_organisationUnit = ""
      @prop_locality = ""
      @prop_state = ""
      @prop_selection = :def # `none, `disk

      @prop_subject_alt_name_list = []
      @prop_adv_cri_issuer_alt_name = false

      @adv_subject_alt_name_show_email = false

      @prop_keep_ca = false

      # variables for new CA/Certificate/Request
      @emailList = []
      @commonName = ""
      @CAName = ""
      @organisation = ""
      @organisationUnit = ""
      @locality = ""
      @state = ""
      @country = "GB"

      @password = ""
      @verifyPassword = ""
      @keyLength = 1024
      @validPeriod = 365

      @adv_cri_ca = false
      @adv_ca = "none"
      @adv_pathlen = false
      @adv_pathlenValue = 1

      @adv_cri_distribution_point = false
      @adv_distribution_point = ""

      @adv_challenge_password = ""

      @adv_cri_issuer_alt_name = false
      @adv_copy_issuer_alt_name = false
      @adv_copy_issuer_alt_name_enabled = false
      @adv_issuer_alt_name_list = []

      @adv_cri_key_usage = false
      @adv_digitalSignature = false
      @adv_nonRepudiation = false
      @adv_cRLSign = false
      @adv_keyEncipherment = false
      @adv_dataEncipherment = false
      @adv_encipherOnly = false
      @adv_keyAgreement = false
      @adv_keyCertSign = false
      @adv_decipherOnly = false

      @adv_cri_nsComment = false
      @adv_nsComment = ""

      @adv_cri_nsCertType = false
      @adv_client = false
      @adv_server = false
      @adv_sslCA = false
      @adv_email = false
      @adv_reserved = false
      @adv_emailCA = false
      @adv_objsign = false
      @adv_objCA = false

      @adv_cri_nsSslServerName = false
      @adv_nsSslServerName = ""

      @adv_cri_subject_alt_name = false
      @adv_copy_subject_alt_name = false
      @adv_subject_alt_name_list = []

      @adv_unstructured_name = ""

      @exp_cri_subjectKeyIdentifier = false
      @exp_subjectKeyIdentifier = ""
      @exp_cri_authorityKeyIdentifier = false
      @exp_authorityKeyIdentifier = ""

      @exp_cri_netscape_nsBaseUrl = false
      @exp_netscape_nsBaseUrl = ""

      @exp_cri_netscape_nsRevocationUrl = false
      @exp_netscape_nsRevocationUrl = ""

      @exp_cri_netscape_nsCaRevocationUrl = false
      @exp_netscape_nsCaRevocationUrl = ""

      @exp_cri_netscape_nsRenewalUrl = false
      @exp_netscape_nsRenewalUrl = ""

      @exp_cri_netscape_nsCaPolicyUrl = false
      @exp_netscape_nsCaPolicyUrl = ""

      @exp_cri_authorityInfoAccess = false
      @exp_authorityInfoAccess = ""

      @exp_cri_extendedKeyUsage = false
      @exp_extendedKeyUsage = "" 



      # EOF
    end

    publish :variable => :autoYaSTSettings, :type => "map"
    publish :variable => :autoYaSTModified, :type => "boolean"
    publish :variable => :certificateSequence, :type => "map"
    publish :variable => :currentDefault, :type => "string"
    publish :variable => :initializeDefault, :type => "boolean"
    publish :variable => :currentCA, :type => "string"
    publish :variable => :currentCertificate, :type => "string"
    publish :variable => :currentRequest, :type => "string"
    publish :variable => :requestKind, :type => "string"
    publish :variable => :requestSubject, :type => "string"
    publish :variable => :requestExtentionValue, :type => "map <string, map>"
    publish :variable => :slectedRequestExtention, :type => "list <string>"
    publish :variable => :validRequestExtention, :type => "list <string>"
    publish :variable => :passwdMap, :type => "map"
    publish :variable => :prop_settingsWritten, :type => "boolean"
    publish :variable => :prop_ca_commonNameChanged, :type => "boolean"
    publish :variable => :prop_ca_commonName, :type => "string"
    publish :variable => :prop_server_commonNameChanged, :type => "boolean"
    publish :variable => :prop_server_commonName, :type => "string"
    publish :variable => :prop_CANameChanged, :type => "boolean"
    publish :variable => :prop_CAName, :type => "string"
    publish :variable => :prop_countryChanged, :type => "boolean"
    publish :variable => :prop_country, :type => "string"
    publish :variable => :prop_passwordChanged, :type => "boolean"
    publish :variable => :prop_password, :type => "string"
    publish :variable => :prop_emailChanged, :type => "boolean"
    publish :variable => :prop_email, :type => "string"
    publish :variable => :prop_organisation, :type => "string"
    publish :variable => :prop_organisationUnit, :type => "string"
    publish :variable => :prop_locality, :type => "string"
    publish :variable => :prop_state, :type => "string"
    publish :variable => :prop_selection, :type => "symbol"
    publish :variable => :prop_subject_alt_name_list, :type => "list <map>"
    publish :variable => :prop_adv_cri_issuer_alt_name, :type => "boolean"
    publish :variable => :adv_subject_alt_name_show_email, :type => "boolean"
    publish :variable => :prop_keep_ca, :type => "boolean"
    publish :variable => :emailList, :type => "list <map>"
    publish :variable => :commonName, :type => "string"
    publish :variable => :CAName, :type => "string"
    publish :variable => :organisation, :type => "string"
    publish :variable => :organisationUnit, :type => "string"
    publish :variable => :locality, :type => "string"
    publish :variable => :state, :type => "string"
    publish :variable => :country, :type => "string"
    publish :variable => :password, :type => "string"
    publish :variable => :verifyPassword, :type => "string"
    publish :variable => :keyLength, :type => "integer"
    publish :variable => :validPeriod, :type => "integer"
    publish :variable => :adv_cri_ca, :type => "boolean"
    publish :variable => :adv_ca, :type => "string"
    publish :variable => :adv_pathlen, :type => "boolean"
    publish :variable => :adv_pathlenValue, :type => "integer"
    publish :variable => :adv_cri_distribution_point, :type => "boolean"
    publish :variable => :adv_distribution_point, :type => "string"
    publish :variable => :adv_challenge_password, :type => "string"
    publish :variable => :adv_cri_issuer_alt_name, :type => "boolean"
    publish :variable => :adv_copy_issuer_alt_name, :type => "boolean"
    publish :variable => :adv_copy_issuer_alt_name_enabled, :type => "boolean"
    publish :variable => :adv_issuer_alt_name_list, :type => "list <map>"
    publish :variable => :adv_cri_key_usage, :type => "boolean"
    publish :variable => :adv_digitalSignature, :type => "boolean"
    publish :variable => :adv_nonRepudiation, :type => "boolean"
    publish :variable => :adv_cRLSign, :type => "boolean"
    publish :variable => :adv_keyEncipherment, :type => "boolean"
    publish :variable => :adv_dataEncipherment, :type => "boolean"
    publish :variable => :adv_encipherOnly, :type => "boolean"
    publish :variable => :adv_keyAgreement, :type => "boolean"
    publish :variable => :adv_keyCertSign, :type => "boolean"
    publish :variable => :adv_decipherOnly, :type => "boolean"
    publish :variable => :adv_cri_nsComment, :type => "boolean"
    publish :variable => :adv_nsComment, :type => "string"
    publish :variable => :adv_cri_nsCertType, :type => "boolean"
    publish :variable => :adv_client, :type => "boolean"
    publish :variable => :adv_server, :type => "boolean"
    publish :variable => :adv_sslCA, :type => "boolean"
    publish :variable => :adv_email, :type => "boolean"
    publish :variable => :adv_reserved, :type => "boolean"
    publish :variable => :adv_emailCA, :type => "boolean"
    publish :variable => :adv_objsign, :type => "boolean"
    publish :variable => :adv_objCA, :type => "boolean"
    publish :variable => :adv_cri_nsSslServerName, :type => "boolean"
    publish :variable => :adv_nsSslServerName, :type => "string"
    publish :variable => :adv_cri_subject_alt_name, :type => "boolean"
    publish :variable => :adv_copy_subject_alt_name, :type => "boolean"
    publish :variable => :adv_subject_alt_name_list, :type => "list <map>"
    publish :variable => :adv_unstructured_name, :type => "string"
    publish :variable => :exp_cri_subjectKeyIdentifier, :type => "boolean"
    publish :variable => :exp_subjectKeyIdentifier, :type => "string"
    publish :variable => :exp_cri_authorityKeyIdentifier, :type => "boolean"
    publish :variable => :exp_authorityKeyIdentifier, :type => "string"
    publish :variable => :exp_cri_netscape_nsBaseUrl, :type => "boolean"
    publish :variable => :exp_netscape_nsBaseUrl, :type => "string"
    publish :variable => :exp_cri_netscape_nsRevocationUrl, :type => "boolean"
    publish :variable => :exp_netscape_nsRevocationUrl, :type => "string"
    publish :variable => :exp_cri_netscape_nsCaRevocationUrl, :type => "boolean"
    publish :variable => :exp_netscape_nsCaRevocationUrl, :type => "string"
    publish :variable => :exp_cri_netscape_nsRenewalUrl, :type => "boolean"
    publish :variable => :exp_netscape_nsRenewalUrl, :type => "string"
    publish :variable => :exp_cri_netscape_nsCaPolicyUrl, :type => "boolean"
    publish :variable => :exp_netscape_nsCaPolicyUrl, :type => "string"
    publish :variable => :exp_cri_authorityInfoAccess, :type => "boolean"
    publish :variable => :exp_authorityInfoAccess, :type => "string"
    publish :variable => :exp_cri_extendedKeyUsage, :type => "boolean"
    publish :variable => :exp_extendedKeyUsage, :type => "string"
  end

  CaMgm = CaMgmClass.new
  CaMgm.main
end
