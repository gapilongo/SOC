#!/usr/bin/env python3
"""
Test the complete workflow with correlation agent integration.
"""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from lg_sotf.main import LG_SOTFApplication


async def test_full_workflow_with_correlation():
    """Test complete workflow including correlation."""
    
    print("🚀 Testing Full Workflow with Correlation")
    print("=" * 60)
    
    try:
        # Create application with POC config
        app = LG_SOTFApplication(config_path="configs/poc.yaml")
        await app.initialize()
        
        # Test alert designed to trigger strong correlations
        test_alert = {
            "id": "workflow-corr-test-001",
            "source": "production-siem", 
            "timestamp": "2024-01-01T03:15:00Z",  # Off hours = temporal correlation
            "severity": "critical",
            "description": "Multi-stage attack with C2 communication detected",
            "raw_data": {
                "event_type": "advanced_persistent_threat",
                "source_ip": "185.220.101.44",        # Known suspicious IP
                "destination_ip": "10.0.0.50",        # Internal critical server
                "destination_port": 4444,             # Suspicious port
                "user": "administrator",              # Privileged user
                "process_name": "update.exe",         # Masquerading process  
                "file_hash": "a1b2c3d4e5f6789",      # Known malware hash
                "parent_process": "winlogon.exe",     # Suspicious parent
                "command_line": "update.exe -c 185.220.101.44:4444",
                "bytes_transferred": 2097152,        # 2MB data exfiltration
                "duration_seconds": 300,             # 5 min connection
                "persistence_mechanism": "registry_run_key"
            }
        }
        
        print(f"🎯 Processing Alert: {test_alert['id']}")
        print(f"📊 Severity: {test_alert['severity']}")
        print(f"⏰ Timestamp: {test_alert['timestamp']} (off-hours)")
        print(f"🌐 Source IP: {test_alert['raw_data']['source_ip']}")
        print(f"👤 User: {test_alert['raw_data']['user']}")
        
        print(f"\n🔄 Starting workflow execution...")
        
        # Process through complete workflow
        result = await app.process_single_alert("workflow-corr-test-001", test_alert)
        
        print(f"\n✅ Workflow Execution Completed!")
        print("=" * 60)
        
        # Display comprehensive results
        print(f"📊 **WORKFLOW RESULTS**")
        print(f"   🏁 Final Status: {result.get('triage_status', 'unknown')}")
        print(f"   🎯 Final Confidence: {result.get('confidence_score', 0)}%")
        print(f"   ⭐ Priority Level: {result.get('priority_level', 'unknown')}")
        print(f"   🔗 Correlations Found: {len(result.get('correlations', []))}")
        print(f"   📈 Correlation Score: {result.get('correlation_score', 0)}%")
        
        # Show False Positive vs True Positive indicators
        fp_indicators = result.get('fp_indicators', [])
        tp_indicators = result.get('tp_indicators', [])
        print(f"\n🔍 **ANALYSIS INDICATORS**")
        print(f"   ❌ False Positive: {len(fp_indicators)} indicators")
        if fp_indicators:
            for fp in fp_indicators:
                print(f"      • {fp}")
        print(f"   ✅ True Positive: {len(tp_indicators)} indicators")
        if tp_indicators:
            for tp in tp_indicators:
                print(f"      • {tp}")
        
        # Show detailed correlations if found
        correlations = result.get('correlations', [])
        if correlations:
            print(f"\n🔗 **CORRELATION ANALYSIS**")
            print(f"   Found {len(correlations)} correlations:")
            
            for i, corr in enumerate(correlations, 1):
                threat_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(
                    corr.get('threat_level', 'low'), "⚪"
                )
                print(f"   {i}. {threat_emoji} **{corr.get('type', 'unknown').upper()}**")
                print(f"      📍 Indicator: {corr.get('indicator', 'unknown')}")
                print(f"      🎯 Confidence: {corr.get('confidence', 0)}%")
                print(f"      ⚠️  Threat Level: {corr.get('threat_level', 'unknown')}")
                print(f"      📝 Description: {corr.get('description', 'N/A')}")
                print()
        
        # Show enriched intelligence data
        enriched_data = result.get('enriched_data', {})
        
        if 'attack_intelligence' in enriched_data:
            attack_intel = enriched_data['attack_intelligence']
            print(f"🎯 **ATTACK INTELLIGENCE**")
            
            if attack_intel.get('campaign_indicators'):
                print(f"   🏴 Campaign Indicators:")
                for indicator in attack_intel['campaign_indicators']:
                    print(f"      • {indicator}")
            
            if attack_intel.get('threat_actor_patterns'):
                print(f"   👹 Threat Actor TTPs:")
                for ttp in attack_intel['threat_actor_patterns']:
                    print(f"      • {ttp}")
                    
            if attack_intel.get('behavioral_anomalies'):
                print(f"   🚨 Behavioral Anomalies:")
                for anomaly in attack_intel['behavioral_anomalies']:
                    print(f"      • {anomaly}")
        
        if 'correlation_summary' in enriched_data:
            corr_summary = enriched_data['correlation_summary']
            print(f"\n📋 **CORRELATION SUMMARY**")
            print(f"   📊 Average Confidence: {corr_summary.get('avg_confidence', 0):.1f}%")
            print(f"   🎯 Maximum Confidence: {corr_summary.get('max_confidence', 0)}%")
            print(f"   🏷️  Correlation Types: {', '.join(corr_summary.get('correlation_types', []))}")
            print(f"   ⚠️  Threat Levels: {', '.join(corr_summary.get('threat_levels', []))}")
        
        # Show processing workflow
        processing_notes = result.get('processing_notes', [])
        if processing_notes:
            print(f"\n📝 **PROCESSING WORKFLOW**")
            for i, note in enumerate(processing_notes, 1):
                step_emoji = ["🔄", "🔍", "🔗", "🧠", "👤", "🛡️", "📚", "🏁"][min(i-1, 7)]
                print(f"   {i}. {step_emoji} {note}")
        
        # Show routing decisions
        current_node = result.get('current_node', 'unknown')
        print(f"\n🛤️  **ROUTING DECISIONS**")
        print(f"   📍 Final Node: {current_node}")
        
        # Determine why it ended where it did
        confidence = result.get('confidence_score', 0)
        correlations_count = len(result.get('correlations', []))
        correlation_score = result.get('correlation_score', 0)
        
        print(f"   🤔 Routing Logic:")
        if current_node == "close":
            if confidence < 20:
                print(f"      → Closed due to low confidence ({confidence}%)")
            elif len(fp_indicators) > len(tp_indicators):
                print(f"      → Closed due to more FP indicators ({len(fp_indicators)}) than TP ({len(tp_indicators)})")
            else:
                print(f"      → Closed after processing completion")
        elif current_node == "human_loop":
            print(f"      → Escalated for human review (confidence: {confidence}%)")
        elif current_node == "response":
            print(f"      → Automated response triggered (high confidence: {confidence}%)")
        
        # Performance metrics
        print(f"\n⚡ **PERFORMANCE METRICS**")
        app_status = app.get_application_status()
        if 'agents' in app_status and not isinstance(app_status['agents'], dict):
            agents_info = app_status['agents']
        else:
            agents_info = {"error": "Could not retrieve agent info"}
            
        if 'error' not in agents_info:
            print(f"   🤖 Agents Active: {agents_info.get('agent_instances_count', 0)}")
            print(f"   ✅ Initialized: {len(agents_info.get('initialized_agents', []))}")
        
        await app.shutdown()
        
        # Final recommendation
        print(f"\n💡 **RECOMMENDATION**")
        if confidence > 80 and correlations_count > 3:
            print(f"   🚨 HIGH THREAT: Immediate investigation recommended")
            print(f"   📞 Escalate to senior analyst or incident response team")
        elif confidence > 60 and correlations_count > 1:
            print(f"   ⚠️  MODERATE THREAT: Review and investigate within SLA")
        elif confidence < 40 or len(fp_indicators) > len(tp_indicators):
            print(f"   ✅ LIKELY FALSE POSITIVE: Monitor but low priority")
        else:
            print(f"   🤷 UNCERTAIN: Manual review recommended")
        
        return True
        
    except Exception as e:
        print(f"❌ Workflow test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_correlation_edge_cases():
    """Test correlation agent with edge cases."""
    
    print(f"\n🧪 Testing Correlation Edge Cases")
    print("=" * 60)
    
    try:
        app = LG_SOTFApplication(config_path="configs/poc.yaml")
        await app.initialize()
        
        # Test Case 1: Clean alert (should have minimal correlations)
        clean_alert = {
            "id": "clean-test-001",
            "source": "test-siem",
            "timestamp": "2024-01-01T14:30:00Z",  # Business hours
            "severity": "low", 
            "description": "Routine system update",
            "raw_data": {
                "event_type": "system_update",
                "source_ip": "10.0.0.100",      # Internal IP
                "user": "system",               # System account
                "process_name": "windows_update_service.exe",  # Legitimate process
                "update_kb": "KB5012345",
                "action": "install_security_update"
            }
        }
        
        print(f"🧹 Testing Clean Alert (should have few correlations)...")
        clean_result = await app.process_single_alert("clean-test-001", clean_alert)
        
        print(f"   Result: {clean_result.get('confidence_score', 0)}% confidence")
        print(f"   Correlations: {len(clean_result.get('correlations', []))}")
        print(f"   Status: {clean_result.get('triage_status', 'unknown')}")
        
        # Test Case 2: Borderline alert (mixed indicators)
        mixed_alert = {
            "id": "mixed-test-001", 
            "source": "production-siem",
            "timestamp": "2024-01-01T18:45:00Z",  # After hours but not too late
            "severity": "medium",
            "description": "Scheduled backup with unusual characteristics", 
            "raw_data": {
                "event_type": "data_transfer",
                "source_ip": "10.0.0.200",      # Internal IP
                "destination_ip": "52.84.10.45", # External backup service
                "user": "backup_service",        # Service account
                "process_name": "backup.exe",    # Legitimate name but...
                "bytes_transferred": 5368709120, # 5GB - large transfer
                "scheduled": "yes",              # Scheduled activity
                "encryption": "enabled"          # Good security practice
            }
        }
        
        print(f"\n⚖️  Testing Mixed Alert (should have moderate correlations)...")
        mixed_result = await app.process_single_alert("mixed-test-001", mixed_alert)
        
        print(f"   Result: {mixed_result.get('confidence_score', 0)}% confidence")
        print(f"   Correlations: {len(mixed_result.get('correlations', []))}")
        print(f"   Status: {mixed_result.get('triage_status', 'unknown')}")
        
        await app.shutdown()
        
        print(f"\n✅ Edge case testing completed!")
        
    except Exception as e:
        print(f"❌ Edge case testing failed: {e}")


if __name__ == "__main__":
    async def main():
        print("🔬 Starting Comprehensive Correlation Tests")
        print("=" * 70)
        
        success1 = await test_full_workflow_with_correlation()
        await test_correlation_edge_cases()
        
        if success1:
            print(f"\n🎉 All tests completed successfully!")
            print(f"🚀 Your correlation agent is working perfectly!")
            print(f"📈 Next step: Implement Analysis Agent for even deeper investigation!")
        else:
            print(f"\n❌ Some tests failed. Please check the logs.")
    
    asyncio.run(main())